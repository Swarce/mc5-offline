package org.mc5offline.patcher;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The player's signing key. The SAME keystore must be reused across every build
 * so Android treats a re-patched APK as an update and keeps the save. If none is
 * supplied and --gen-key is set, a fresh long-lived key is created and its path
 * is printed so the player keeps it.
 */
final class Keystore {
    private final File store;
    private final String storePass;
    private final String alias;
    private final String keyPass;

    private Keystore(File store, String storePass, String alias, String keyPass) {
        this.store = store;
        this.storePass = storePass;
        this.alias = alias;
        this.keyPass = keyPass;
    }

    static Keystore resolve(Map<String, List<String>> o, String keytool, boolean genKey)
            throws IOException {
        String path = last(o, "ks");
        String storePass = last(o, "ks-pass");
        String alias = last(o, "ks-alias");
        if (alias == null) alias = "mc5";
        String keyPass = last(o, "ks-key-pass");

        if (path == null) {
            if (!genKey)
                throw new IllegalArgumentException(
                        "no --ks given; pass --ks <keystore> (reuse the same one every build) "
                        + "or --gen-key to create one");
            path = "mc5-offline.keystore";
        }
        if (storePass == null) storePass = "mc5offline";
        if (keyPass == null) keyPass = storePass;

        File store = new File(path);
        if (!store.exists()) {
            if (!genKey)
                throw new IllegalArgumentException("keystore not found: " + path
                        + " (add --gen-key to create it)");
            generate(keytool, store, storePass, alias, keyPass);
            System.out.println("generated keystore " + store.getAbsolutePath()
                    + " (alias=" + alias + ") — KEEP THIS FILE; updates need the same key.");
        }
        return new Keystore(store, storePass, alias, keyPass);
    }

    private static void generate(String keytool, File store, String storePass,
                                 String alias, String keyPass) throws IOException {
        Proc.checked(List.of(
                keytool, "-genkeypair", "-noprompt",
                "-keystore", store.getAbsolutePath(),
                "-storepass", storePass,
                "-keypass", keyPass,
                "-alias", alias,
                "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "10000",
                "-dname", "CN=MC5 Offline, OU=Preservation, O=MC5 Offline, C=US"));
    }

    void sign(String apksigner, File apk, int minSdk) throws IOException {
        List<String> cmd = new ArrayList<>(List.of(
                apksigner, "sign",
                "--ks", store.getAbsolutePath(),
                "--ks-key-alias", alias,
                "--ks-pass", "pass:" + storePass,
                "--key-pass", "pass:" + keyPass,
                "--v1-signing-enabled", "false",
                "--v2-signing-enabled", "true",
                "--v3-signing-enabled", "true",
                "--v4-signing-enabled", "false",
                "--min-sdk-version", String.valueOf(minSdk),
                apk.getAbsolutePath()));
        Proc.checked(cmd);
    }

    private static String last(Map<String, List<String>> o, String k) {
        List<String> v = o.get(k);
        return (v == null || v.isEmpty()) ? null : v.get(v.size() - 1);
    }
}
