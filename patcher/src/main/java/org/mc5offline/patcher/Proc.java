package org.mc5offline.patcher;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

/** Minimal helper for running external SDK tools (zipalign, apksigner, keytool). */
final class Proc {
    private Proc() {}

    static final class Result {
        final int code;
        final String out;
        Result(int code, String out) { this.code = code; this.out = out; }
    }

    /** Runs a command, capturing stdout+stderr together. Never throws on non-zero. */
    static Result run(List<String> cmd) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (InputStream in = p.getInputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) >= 0) bos.write(buf, 0, n);
        }
        int code;
        try {
            code = p.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted waiting for " + cmd.get(0), e);
        }
        return new Result(code, bos.toString());
    }

    /** Runs a command and throws with the captured output if it exits non-zero. */
    static String checked(List<String> cmd) throws IOException {
        Result r = run(cmd);
        if (r.code != 0) {
            throw new IOException(cmd.get(0) + " exited " + r.code + ":\n" + r.out);
        }
        return r.out;
    }
}
