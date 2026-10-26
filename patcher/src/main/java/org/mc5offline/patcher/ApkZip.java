package org.mc5offline.patcher;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * Copies an APK to a new file, optionally replacing some entries and appending
 * new stored entries, while always stripping any existing v1 (JAR) signature so
 * the result can be re-signed cleanly with the player's key.
 *
 * Native libraries and resources.arsc are written STORED (uncompressed) because
 * the app declares android:extractNativeLibs="false"; zipalign -p then page-aligns
 * them. Everything else keeps its original compression method.
 */
final class ApkZip {
    private ApkZip() {}

    static boolean isOldSignatureEntry(String name) {
        if (name.equals("META-INF/MANIFEST.MF")) return true;
        if (!name.startsWith("META-INF/")) return false;
        String upper = name.toUpperCase();
        return upper.endsWith(".SF") || upper.endsWith(".RSA")
                || upper.endsWith(".DSA") || upper.endsWith(".EC");
    }

    private static boolean mustStore(String name, int originalMethod) {
        return name.endsWith(".so")
                || name.equals("resources.arsc")
                || originalMethod == ZipEntry.STORED;
    }

    static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[1 << 16];
        int n;
        while ((n = in.read(buf)) >= 0) bos.write(buf, 0, n);
        return bos.toByteArray();
    }

    /**
     * @param in        source APK
     * @param out       destination APK (overwritten)
     * @param replace   entryName -> new bytes (same name replaced in place)
     * @param addStored entryName -> bytes, added STORED if not already present
     */
    static void rewrite(File in, File out,
                        Map<String, byte[]> replace,
                        Map<String, byte[]> addStored) throws IOException {
        Set<String> seen = new HashSet<>();
        try (ZipFile zf = new ZipFile(in);
             ZipOutputStream zos = new ZipOutputStream(
                     new BufferedOutputStream(new FileOutputStream(out), 1 << 20))) {
            Enumeration<? extends ZipEntry> en = zf.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                String name = e.getName();
                if (isOldSignatureEntry(name)) continue; // drop stale signatures
                byte[] data = replace.containsKey(name)
                        ? replace.get(name)
                        : readAll(zf.getInputStream(e));
                writeEntry(zos, name, data, mustStore(name, e.getMethod()));
                seen.add(name);
            }
            for (Map.Entry<String, byte[]> add : addStored.entrySet()) {
                if (seen.contains(add.getKey())) continue;
                writeEntry(zos, add.getKey(), add.getValue(), true);
            }
        }
    }

    private static void writeEntry(ZipOutputStream zos, String name, byte[] data, boolean stored)
            throws IOException {
        ZipEntry ne = new ZipEntry(name);
        if (stored) {
            ne.setMethod(ZipEntry.STORED);
            ne.setSize(data.length);
            ne.setCompressedSize(data.length);
            CRC32 crc = new CRC32();
            crc.update(data);
            ne.setCrc(crc.getValue());
        } else {
            ne.setMethod(ZipEntry.DEFLATED);
        }
        zos.putNextEntry(ne);
        zos.write(data);
        zos.closeEntry();
    }

    static void copyStream(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[1 << 16];
        int n;
        while ((n = in.read(buf)) >= 0) out.write(buf, 0, n);
    }
}
