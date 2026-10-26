package org.mc5offline.patcher;

import org.jf.dexlib2.AccessFlags;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.builder.MutableMethodImplementation;
import org.jf.dexlib2.builder.instruction.BuilderInstruction10x;
import org.jf.dexlib2.builder.instruction.BuilderInstruction21c;
import org.jf.dexlib2.builder.instruction.BuilderInstruction35c;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.iface.MultiDexContainer;
import org.jf.dexlib2.immutable.ImmutableClassDef;
import org.jf.dexlib2.immutable.ImmutableDexFile;
import org.jf.dexlib2.immutable.ImmutableMethod;
import org.jf.dexlib2.immutable.reference.ImmutableMethodReference;
import org.jf.dexlib2.immutable.reference.ImmutableStringReference;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The one surgical dex edit, done structurally through dexlib2 (never by raw
 * bytes): add a tiny bootstrap class and make the game's Application call it
 * before anything else, so libmc5offline.so loads ahead of libMC5.so.
 *
 *   class com.gameloft.android.ANMP.GloftM5HM.MC5Offline {
 *       static void boot() { System.loadLibrary("mc5offline"); }
 *   }
 *
 * and, prepended to the earliest lifecycle method of FrameworkApplication, a
 * zero-register:  invoke-static {}, MC5Offline->boot()V
 *
 * Zero registers means no register reallocation in the host method, so the edit
 * is minimal and verifier-safe.
 */
final class DexPatch {

    static final String APP_CLASS = "Lcom/gameloft/android/ANMP/GloftM5HM/FrameworkApplication;";
    static final String BOOT_CLASS = "Lcom/gameloft/android/ANMP/GloftM5HM/MC5Offline;";
    static final String BOOT_METHOD = "boot";
    static final String LIB_NAME = "mc5offline";

    // Candidate host methods, earliest first.
    private static final String[][] TARGETS = {
        {"attachBaseContext", "V", "Landroid/content/Context;"},
        {"onCreate", "V"},
        {"<init>", "V"},
    };

    /** Result of locating the application class inside a multidex APK. */
    static final class Plan {
        final String dexEntry;        // e.g. "classes.dex"
        final String hostMethod;      // method name the boot call is prepended to
        final String hostMethodDesc;  // human-readable signature
        final String appDexSha256;    // sha-256 of the original dex being edited
        Plan(String dexEntry, String hostMethod, String hostMethodDesc, String appDexSha256) {
            this.dexEntry = dexEntry;
            this.hostMethod = hostMethod;
            this.hostMethodDesc = hostMethodDesc;
            this.appDexSha256 = appDexSha256;
        }
    }

    /**
     * Finds the dex holding FrameworkApplication and the earliest lifecycle method
     * present on it. Throws if the class (the fingerprint for this edit) is absent.
     */
    static Plan locate(File apk) throws Exception {
        MultiDexContainer<? extends DexBackedDexFile> c =
                DexFileFactory.loadDexContainer(apk, Opcodes.getDefault());
        for (String entry : c.getDexEntryNames()) {
            // The app's own dex are classes*.dex at the root; assets/*/classes*.dex
            // belong to a dynamically loaded SDK and are not the boot classpath.
            if (entry.contains("/")) continue;
            DexFile dex = c.getEntry(entry).getDexFile();
            for (ClassDef cls : dex.getClasses()) {
                if (!cls.getType().equals(APP_CLASS)) continue;
                String[] target = pickTarget(cls);
                if (target == null) {
                    throw new IllegalStateException(
                            "FrameworkApplication has none of the expected lifecycle methods "
                            + "(attachBaseContext/onCreate/<init>); refusing to guess.");
                }
                String sha = Fingerprint.sha256Hex(
                        c.getEntry(entry).getDexFile() != null
                                ? readEntryBytes(apk, entry) : new byte[0]);
                return new Plan(entry, target[0], describe(target), sha);
            }
        }
        throw new IllegalStateException("FrameworkApplication not found in any root dex; "
                + "this APK is not the expected MC5 base split.");
    }

    private static byte[] readEntryBytes(File apk, String entry) throws Exception {
        try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(apk)) {
            java.util.zip.ZipEntry e = zf.getEntry(entry);
            return ApkZip.readAll(zf.getInputStream(e));
        }
    }

    private static String describe(String[] t) {
        StringBuilder sb = new StringBuilder(t[0]).append('(');
        for (int i = 2; i < t.length; i++) sb.append(t[i]);
        return sb.append(')').append(t[1]).toString();
    }

    private static String[] pickTarget(ClassDef cls) {
        for (String[] t : TARGETS) {
            for (Method m : cls.getMethods()) {
                if (!m.getName().equals(t[0])) continue;
                if (!m.getReturnType().equals(t[1])) continue;
                if (m.getParameterTypes().size() != t.length - 2) continue;
                boolean ok = true;
                for (int i = 2; i < t.length; i++) {
                    if (!m.getParameterTypes().get(i - 2).toString().equals(t[i])) { ok = false; break; }
                }
                if (ok && m.getImplementation() != null) return t;
            }
        }
        return null;
    }

    /**
     * Rewrites the located dex: appends MC5Offline and prepends the boot call to
     * the chosen host method. Returns the new dex bytes.
     */
    static byte[] buildPatchedDex(File apk, Plan plan) throws Exception {
        MultiDexContainer<? extends DexBackedDexFile> c =
                DexFileFactory.loadDexContainer(apk, Opcodes.getDefault());
        DexBackedDexFile dex = c.getEntry(plan.dexEntry).getDexFile();
        Opcodes opcodes = dex.getOpcodes();

        List<ClassDef> out = new ArrayList<>();
        boolean patched = false;
        for (ClassDef cls : dex.getClasses()) {
            if (cls.getType().equals(APP_CLASS)) {
                out.add(patchAppClass(cls, plan.hostMethod));
                patched = true;
            } else {
                out.add(cls);
            }
        }
        if (!patched) throw new IllegalStateException("app class vanished between locate and patch");
        out.add(bootClass());

        File tmp = File.createTempFile("mc5-dex", ".dex");
        tmp.deleteOnExit();
        DexFile result = new ImmutableDexFile(opcodes, out);
        DexFileFactory.writeDexFile(tmp.getAbsolutePath(), result);
        byte[] bytes = Files.readAllBytes(tmp.toPath());
        tmp.delete();
        return bytes;
    }

    private static ClassDef patchAppClass(ClassDef cls, String hostMethod) {
        List<Method> methods = new ArrayList<>();
        for (Method m : cls.getMethods()) {
            if (m.getName().equals(hostMethod) && m.getImplementation() != null
                    && !alreadyHasBootCall(m)) {
                methods.add(prependBootCall(m));
            } else {
                methods.add(m);
            }
        }
        return new ImmutableClassDef(
                cls.getType(), cls.getAccessFlags(), cls.getSuperclass(),
                cls.getInterfaces(), cls.getSourceFile(), cls.getAnnotations(),
                cls.getFields(), methods);
    }

    private static boolean alreadyHasBootCall(Method m) {
        MethodImplementation impl = m.getImplementation();
        if (impl == null) return false;
        for (var insn : impl.getInstructions()) {
            if (insn instanceof org.jf.dexlib2.iface.instruction.ReferenceInstruction ri
                    && ri.getReference() instanceof org.jf.dexlib2.iface.reference.MethodReference mr
                    && mr.getDefiningClass().equals(BOOT_CLASS)
                    && mr.getName().equals(BOOT_METHOD)) {
                return true;
            }
        }
        return false;
    }

    private static Method prependBootCall(Method m) {
        MutableMethodImplementation impl = new MutableMethodImplementation(m.getImplementation());
        ImmutableMethodReference bootRef = new ImmutableMethodReference(
                BOOT_CLASS, BOOT_METHOD, Collections.emptyList(), "V");
        // invoke-static {}, MC5Offline->boot()V   (zero registers)
        impl.addInstruction(0, new BuilderInstruction35c(
                Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, bootRef));
        return new ImmutableMethod(
                m.getDefiningClass(), m.getName(), m.getParameters(), m.getReturnType(),
                m.getAccessFlags(), m.getAnnotations(), m.getHiddenApiRestrictions(), impl);
    }

    private static ClassDef bootClass() {
        MutableMethodImplementation impl = new MutableMethodImplementation(1);
        impl.addInstruction(new BuilderInstruction21c(
                Opcode.CONST_STRING, 0, new ImmutableStringReference(LIB_NAME)));
        impl.addInstruction(new BuilderInstruction35c(
                Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0,
                new ImmutableMethodReference(
                        "Ljava/lang/System;", "loadLibrary",
                        Collections.singletonList("Ljava/lang/String;"), "V")));
        impl.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));

        ImmutableMethod boot = new ImmutableMethod(
                BOOT_CLASS, BOOT_METHOD, Collections.emptyList(), "V",
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(),
                Collections.emptySet(), Collections.emptySet(), impl);

        return new ImmutableClassDef(
                BOOT_CLASS,
                AccessFlags.PUBLIC.getValue() | AccessFlags.FINAL.getValue(),
                "Ljava/lang/Object;",
                null, null, Collections.emptySet(),
                Collections.emptyList(),
                Collections.singletonList(boot));
    }

    /** For --info: list FrameworkApplication's methods so the host target is auditable. */
    static List<String> listAppMethods(File apk) throws Exception {
        MultiDexContainer<? extends DexBackedDexFile> c =
                DexFileFactory.loadDexContainer(apk, Opcodes.getDefault());
        List<String> lines = new ArrayList<>();
        for (String entry : c.getDexEntryNames()) {
            if (entry.contains("/")) continue;
            DexFile dex = c.getEntry(entry).getDexFile();
            for (ClassDef cls : dex.getClasses()) {
                if (!cls.getType().equals(APP_CLASS)) continue;
                lines.add("in " + entry + ":");
                for (Method m : cls.getMethods()) {
                    StringBuilder sb = new StringBuilder("  ").append(m.getName()).append('(');
                    for (var p : m.getParameterTypes()) sb.append(p);
                    sb.append(')').append(m.getReturnType());
                    if (m.getImplementation() == null) sb.append("  [no body]");
                    lines.add(sb.toString());
                }
                return lines;
            }
        }
        lines.add("FrameworkApplication not found");
        return lines;
    }
}
