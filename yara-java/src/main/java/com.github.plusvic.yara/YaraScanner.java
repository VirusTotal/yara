package com.github.plusvic.yara;

import org.fusesource.hawtjni.runtime.Callback;

import java.io.File;
import java.io.IOException;

/**
 * User: pba
 * Date: 6/7/15
 * Time: 10:06 AM
 */
public class YaraScanner implements AutoCloseable {
    private static final long CALLBACK_MSG_RULE_MATCHING = 1;

    private class NativeScanCallback {
        private final YaraLibrary library;
        private final YaraScanCallback callback;

        public NativeScanCallback(YaraLibrary library, YaraScanCallback callback) {
            this.library = library;
            this.callback = callback;
        }

        long nativeOnScan(long type, long message, long data) {
            if (type == CALLBACK_MSG_RULE_MATCHING) {
                YaraRule rule = new YaraRule(library, message);
                callback.onMatch(rule);
            }
            return 0;
        }
    }

    private YaraLibrary library;
    private Callback    callback;
    private long        peer;
    private int         timeout = 60;

    YaraScanner(YaraLibrary library, long rules) {
        Preconditions.checkArgument(library != null);
        Preconditions.checkArgument(rules != 0);

        this.library = library;
        this.peer = rules;
    }

    @Override
    protected void finalize() throws Throwable {
        close();
        super.finalize();
    }

    @Override
    public void close() throws IOException {
        if (callback != null) {
            callback.dispose();
            callback = null;
        }

        if (peer != 0) {
            library.yr_rules_destroy(peer);
            peer = 0;
        }
        library = null;
    }

    /**
     * Set scan timeout
     */
    public void setTimeout(int timeout) {
        Preconditions.checkArgument(timeout >= 0);
        this.timeout = timeout;
    }

    /**
     * Set scan callback
     * @param cbk
     */
    public void setCallback(YaraScanCallback cbk) {
        Preconditions.checkArgument(cbk != null);
        Preconditions.checkState(callback == null);

        callback = new Callback(new NativeScanCallback(library, cbk), "nativeOnScan", 3);
    }

    /**
     * Scan file
     * @param file
     */
    public void scan(File file) {
        Preconditions.checkState(callback != null);
        library.yr_rules_scan_file(peer, file.getAbsolutePath(), 0, callback.getAddress(), 0, timeout);
    }
}
