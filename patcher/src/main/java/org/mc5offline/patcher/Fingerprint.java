package org.mc5offline.patcher;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;

/** SHA-256 helpers for the dry-run / reproducibility reporting. */
final class Fingerprint {
    private Fingerprint() {}

    static String sha256Hex(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return hex(md.digest(data));
    }

    static String sha256Hex(File f) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] buf = new byte[1 << 16];
        try (InputStream in = new FileInputStream(f)) {
            int n;
            while ((n = in.read(buf)) >= 0) md.update(buf, 0, n);
        }
        return hex(md.digest());
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(Character.forDigit((x >> 4) & 0xf, 16))
                           .append(Character.forDigit(x & 0xf, 16));
        return sb.toString();
    }
}
