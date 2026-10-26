package org.mc5offline.patcher;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MC5 Offline patcher.
 *
 * Input: the player's own MC5 6.0.12a split set (base + abi split + density
 * split + asset packs) and the freshly built libmc5offline.so per ABI.
 * Output: the same split set, re-signed with the player's single key, with
 * libmc5offline.so added to each abi split and the game's Application made to
 * load it first — ready for `adb install-multiple`.
 *
 * Gameloft binaries are never redistributed: everything comes from the player's
 * own files and goes back out signed by the player's own key. The one code edit
 * (the dex) is done structurally and is fingerprinted and dry-runnable.
 */
public final class MC5Patch {

    static final String EXPECTED_PKG = "com.gameloft.android.ANMP.GloftM5HM";
    static final String EXPECTED_VERSIONCODE = "601213";

    public static void main(String[] args) {
        try {
            if (args.length == 0) { usage(); System.exit(2); return; }
            String cmd = args[0];
            Map<String, List<String>> opt = parse(args);
            switch (cmd) {
                case "info":  info(opt);  break;
                case "patch": patch(opt); break;
                default: usage(); System.exit(2);
            }
        } catch (Exception e) {
            System.err.println("error: " + e.getMessage());
            System.exit(1);
        }
    }

    // ---- option parsing -------------------------------------------------

    private static Map<String, List<String>> parse(String[] args) {
        Map<String, List<String>> m = new HashMap<>();
        for (int i = 1; i < args.length; i++) {
            String a = args[i];
            if (!a.startsWith("--")) throw new IllegalArgumentException("unexpected arg: " + a);
            String key = a.substring(2);
            String val = "true";
            if (i + 1 < args.length && !args[i + 1].startsWith("--")) val = args[++i];
            m.computeIfAbsent(key, k -> new ArrayList<>()).add(val);
        }
        return m;
    }

    private static String one(Map<String, List<String>> o, String k, String dflt) {
        List<String> v = o.get(k);
        return (v == null || v.isEmpty()) ? dflt : v.get(v.size() - 1);
    }
    private static boolean flag(Map<String, List<String>> o, String k) { return o.containsKey(k); }
    private static List<String> many(Map<String, List<String>> o, String k) {
        return o.getOrDefault(k, new ArrayList<>());
    }

    private static Map<String, String> pairs(List<String> raw) {
        Map<String, String> m = new LinkedHashMap<>();
        for (String r : raw) {
            int eq = r.indexOf('=');
            if (eq < 0) throw new IllegalArgumentException("expected key=value, got: " + r);
            m.put(r.substring(0, eq), r.substring(eq + 1));
        }
        return m;
    }

    // ---- build-tools discovery -----------------------------------------

    private static String buildTools(Map<String, List<String>> o) {
        String bt = one(o, "build-tools", System.getenv("MC5_BUILD_TOOLS"));
        if (bt == null) bt = "/home/user/tools/android-sdk/build-tools/34.0.0";
        if (!new File(bt, "aapt2").exists() && !new File(bt, "aapt2.exe").exists())
            throw new IllegalArgumentException("build-tools not found at " + bt
                    + " (pass --build-tools <dir> or set MC5_BUILD_TOOLS)");
        return bt;
    }
    private static String tool(String bt, String name) {
        File f = new File(bt, name);
        if (f.exists()) return f.getAbsolutePath();
        File exe = new File(bt, name + ".exe");
        if (exe.exists()) return exe.getAbsolutePath();
        return new File(bt, name).getAbsolutePath();
    }
    private static String keytool() {
        String home = System.getProperty("java.home");
        File f = new File(home, "bin/keytool");
        if (f.exists()) return f.getAbsolutePath();
        File exe = new File(home, "bin/keytool.exe");
        if (exe.exists()) return exe.getAbsolutePath();
        return "keytool";
    }

    // ---- info -----------------------------------------------------------

    private static void info(Map<String, List<String>> o) throws Exception {
        File base = required(o, "base");
        String bt = buildTools(o);
        String[] pv = badging(bt, base);
        System.out.println("base: " + base.getName());
        System.out.println("  package=" + pv[0] + " versionCode=" + pv[1] + " versionName=" + pv[2]);
        checkIdentity(pv, flag(o, "force"));
        System.out.println("  sha256=" + Fingerprint.sha256Hex(base));
        System.out.println("application class methods:");
        for (String line : DexPatch.listAppMethods(base)) System.out.println("  " + line);
        DexPatch.Plan plan = DexPatch.locate(base);
        System.out.println("plan: edit " + plan.dexEntry + ", prepend boot() to "
                + plan.hostMethod + " (" + plan.hostMethodDesc + ")");
        System.out.println("      original " + plan.dexEntry + " sha256=" + plan.appDexSha256);
    }

    // ---- patch ----------------------------------------------------------

    private static void patch(Map<String, List<String>> o) throws Exception {
        File base = required(o, "base");
        String bt = buildTools(o);
        boolean dry = flag(o, "dry-run");
        int minSdk = Integer.parseInt(one(o, "min-sdk", "24"));

        Map<String, String> abiSplits = pairs(many(o, "abi-split")); // abi -> apk
        Map<String, String> libs = pairs(many(o, "lib"));            // abi -> so
        List<String> otherSplits = many(o, "split");                 // density/lang apks
        List<String> packs = many(o, "pack");                        // asset packs

        // 1. Fingerprint the base identity before touching anything.
        String[] pv = badging(bt, base);
        System.out.println("base " + base.getName() + ": package=" + pv[0]
                + " versionCode=" + pv[1] + " versionName=" + pv[2]);
        checkIdentity(pv, flag(o, "force"));

        // 2. Locate the dex edit (fails loudly if the class/method is missing).
        DexPatch.Plan plan = DexPatch.locate(base);
        System.out.println("dex edit: " + plan.dexEntry + " -> prepend MC5Offline.boot() to "
                + plan.hostMethod + " (" + plan.hostMethodDesc + ")");
        System.out.println("          original " + plan.dexEntry + " sha256=" + plan.appDexSha256);

        // Report the full plan.
        System.out.println("abi splits:");
        for (var e : abiSplits.entrySet()) {
            String so = libs.get(e.getKey());
            System.out.println("  " + e.getKey() + ": " + new File(e.getValue()).getName()
                    + (so != null ? "  + lib/" + e.getKey() + "/libmc5offline.so" : "  (NO LIB for this abi!)"));
        }
        for (String s : otherSplits) System.out.println("  split (re-sign only): " + new File(s).getName());
        for (String p : packs) System.out.println("  asset pack (re-sign only): " + new File(p).getName());

        if (dry) {
            System.out.println("\n[dry-run] no files written. Re-run without --dry-run to produce the set.");
            return;
        }

        File outDir = new File(required1(o, "out"));
        if (!outDir.exists() && !outDir.mkdirs())
            throw new IOException("cannot create out dir " + outDir);

        // Keystore (same key across builds keeps the player's save on update).
        Keystore ks = Keystore.resolve(o, keytool(), flag(o, "gen-key"));

        List<File> outputs = new ArrayList<>();

        // 3a. base: inject the patched dex.
        byte[] patchedDex = DexPatch.buildPatchedDex(base, plan);
        Map<String, byte[]> replace = new HashMap<>();
        replace.put(plan.dexEntry, patchedDex);
        File outBase = new File(outDir, base.getName());
        ApkZip.rewrite(base, outBase, replace, new HashMap<>());
        System.out.println("wrote " + outBase.getName() + " (patched " + plan.dexEntry
                + " -> sha256=" + Fingerprint.sha256Hex(patchedDex) + ")");
        outputs.add(outBase);

        // 3b. abi splits: add libmc5offline.so.
        for (var e : abiSplits.entrySet()) {
            File split = new File(e.getValue());
            Map<String, byte[]> add = new HashMap<>();
            String so = libs.get(e.getKey());
            if (so != null) {
                byte[] soBytes = Files.readAllBytes(new File(so).toPath());
                add.put("lib/" + e.getKey() + "/libmc5offline.so", soBytes);
            }
            File out = new File(outDir, split.getName());
            ApkZip.rewrite(split, out, new HashMap<>(), add);
            System.out.println("wrote " + out.getName()
                    + (so != null ? " (+libmc5offline.so)" : " (re-signed only)"));
            outputs.add(out);
        }

        // 3c. other splits and asset packs: strip old signature, re-sign.
        for (String s : otherSplits) outputs.add(copyStrip(new File(s), outDir));
        for (String p : packs)       outputs.add(copyStrip(new File(p), outDir));

        // 4. align + sign + verify every output.
        for (File apk : outputs) {
            zipalign(bt, apk);
            ks.sign(tool(bt, "apksigner"), apk, minSdk);
            verify(bt, apk, minSdk);
        }

        // 5. install helper.
        writeInstallScript(outDir, outputs);

        System.out.println("\nDONE. " + outputs.size() + " APKs in " + outDir.getAbsolutePath());
        for (File apk : outputs)
            System.out.println("  " + apk.getName() + "  sha256=" + Fingerprint.sha256Hex(apk));
        System.out.println("Install:  bash " + new File(outDir, "install-set.sh").getAbsolutePath());
    }

    private static File copyStrip(File in, File outDir) throws IOException {
        File out = new File(outDir, in.getName());
        ApkZip.rewrite(in, out, new HashMap<>(), new HashMap<>());
        System.out.println("wrote " + out.getName() + " (re-signed only)");
        return out;
    }

    // ---- external tool steps -------------------------------------------

    private static String[] badging(String bt, File apk) throws IOException {
        String out = Proc.checked(List.of(tool(bt, "aapt2"), "dump", "badging", apk.getAbsolutePath()));
        Matcher m = Pattern.compile(
                "package: name='([^']+)' versionCode='([^']+)' versionName='([^']*)'").matcher(out);
        if (!m.find()) throw new IOException("could not read package info from " + apk.getName());
        return new String[]{m.group(1), m.group(2), m.group(3)};
    }

    private static void checkIdentity(String[] pv, boolean force) {
        boolean ok = EXPECTED_PKG.equals(pv[0]) && EXPECTED_VERSIONCODE.equals(pv[1]);
        if (!ok) {
            String msg = "base is " + pv[0] + " " + pv[1] + ", expected "
                    + EXPECTED_PKG + " " + EXPECTED_VERSIONCODE;
            if (!force) throw new IllegalStateException(msg + " (pass --force to override)");
            System.out.println("WARNING: " + msg + " (--force)");
        }
    }

    private static void zipalign(String bt, File apk) throws IOException {
        File aligned = new File(apk.getAbsolutePath() + ".aligned");
        Proc.checked(List.of(tool(bt, "zipalign"), "-p", "-f", "4",
                apk.getAbsolutePath(), aligned.getAbsolutePath()));
        if (!aligned.renameTo(apk)) {
            Files.move(aligned.toPath(), apk.toPath(),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void verify(String bt, File apk, int minSdk) throws IOException {
        Proc.Result r = Proc.run(List.of(tool(bt, "apksigner"), "verify",
                "--min-sdk-version", String.valueOf(minSdk), apk.getAbsolutePath()));
        if (r.code != 0)
            throw new IOException("apksigner verify failed for " + apk.getName() + ":\n" + r.out);
    }

    private static void writeInstallScript(File outDir, List<File> apks) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("#!/usr/bin/env bash\n");
        sb.append("# Install the MC5 Offline split set in one atomic session.\n");
        sb.append("# If a Play-Store copy is installed, uninstall it first (different\n");
        sb.append("# signing key). Re-running this over a previous MC5 Offline build keeps\n");
        sb.append("# the save, because every build is signed with the same key.\n");
        sb.append("# Add -g after install-multiple to also grant runtime permissions.\n");
        sb.append("set -e\n");
        sb.append("ADB=\"${ADB:-adb}\"\n");
        sb.append("\"$ADB\" install-multiple -r \\\n");
        for (int i = 0; i < apks.size(); i++) {
            sb.append("  \"$(dirname \"$0\")/").append(apks.get(i).getName()).append('"');
            sb.append(i < apks.size() - 1 ? " \\\n" : "\n");
        }
        File f = new File(outDir, "install-set.sh");
        Files.write(f.toPath(), sb.toString().getBytes(StandardCharsets.UTF_8));
        f.setExecutable(true);
    }

    // ---- helpers --------------------------------------------------------

    private static File required(Map<String, List<String>> o, String k) {
        String v = one(o, k, null);
        if (v == null) throw new IllegalArgumentException("--" + k + " is required");
        File f = new File(v);
        if (!f.exists()) throw new IllegalArgumentException(k + " not found: " + v);
        return f;
    }
    private static String required1(Map<String, List<String>> o, String k) {
        String v = one(o, k, null);
        if (v == null) throw new IllegalArgumentException("--" + k + " is required");
        return v;
    }

    private static void usage() {
        System.out.println(String.join("\n",
            "MC5 Offline patcher",
            "",
            "  info  --base <base.apk> [--build-tools <dir>]",
            "        Fingerprint the base and show the dex edit plan.",
            "",
            "  patch --base <base.apk> --out <dir>",
            "        [--abi-split arm64-v8a=<config.arm64_v8a.apk>] (repeatable)",
            "        [--lib arm64-v8a=<libmc5offline.so>] (repeatable)",
            "        [--split <config.xxhdpi.apk>] (repeatable, re-signed only)",
            "        [--pack <assetPack.apk>] (repeatable, re-signed only)",
            "        [--ks <keystore>] [--ks-pass <pass>] [--ks-alias <alias>] [--ks-key-pass <pass>]",
            "        [--gen-key] [--min-sdk 24] [--build-tools <dir>] [--dry-run] [--force]",
            "",
            "  All inputs are the player's own files; outputs are re-signed with the player's key."));
    }
}
