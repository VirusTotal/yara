package com.github.plusvic.yara;

import org.fusesource.hawtjni.runtime.Callback;

/**
 * Yara compiler
 */
public class YaraCompiler implements AutoCloseable {
    /**
     * Native compilation callback wrapper
     */
    private class NativeCompilationCallback {
        private final YaraLibrary library;
        private final YaraCompilationCallback callback;

        public NativeCompilationCallback(YaraLibrary library, YaraCompilationCallback callback) {
            this.library = library;
            this.callback = callback;
        }

        long nativeOnError(long errorLevel, long fileName, long lineNumber, long message, long data) {
            callback.onError(YaraCompilationCallback.ErrorLevel.from((int) errorLevel),
                    library.cast_jstring(null, fileName),
                    lineNumber,
                    library.cast_jstring(null, message));
            return 0;
        }
    }

    private YaraLibrary library;
    private long        peer;
    private Callback    callback;

    YaraCompiler(YaraLibrary library, long compiler) {
        Preconditions.checkArgument(library != null);
        Preconditions.checkArgument(compiler != 0);

        this.library = library;
        this.peer = compiler;
    }

    @Override
    protected void finalize() throws Throwable {
        close();
        super.finalize();
    }

    /**
     * Set compilation callback
     * @param cbk
     */
    public void setCallback(YaraCompilationCallback cbk) {
        Preconditions.checkArgument(cbk != null);
        Preconditions.checkState(callback == null);

        callback = new Callback(new NativeCompilationCallback(library, cbk), "nativeOnError", 5);
        library.yr_compiler_set_callback(peer, callback.getAddress(), 0);
    }

    /**
     * Release compiler instance
     * @throws Exception
     */
    public void close() throws Exception {
        if (callback != null) {
            callback.dispose();
            callback = null;
        }

        if (peer != 0) {
            library.yr_compiler_destroy(peer);
            peer = 0;
        }

        library = null;
    }

    /**
     * Add rules content
     * @param content
     * @param namespace
     * @return
     */
    public boolean addRules(String content, String namespace) {
        return 0 == library.yr_compiler_add_string(peer, content, namespace);
    }

    /**
     * Create scanner
     * @return
     */
    public YaraScanner createScanner() {
        int ret = 0;

        long rules[] = new long[1];
        if (0 != (ret = library.yr_compiler_get_rules(peer, rules))) {
            throw new YaraException(ret);
        }

        return new YaraScanner(library, rules[0]);
    }
}
