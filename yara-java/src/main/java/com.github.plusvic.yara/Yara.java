package com.github.plusvic.yara;

/**
 * Yara component
 * @apiNote There should be only one component instance per process
 *
 */
public class Yara implements AutoCloseable {
    private final YaraLibrary library;

    public Yara() {
        library = new YaraLibrary();
        library.yr_initialize();
    }

    /**
     * Create compiler
     * @return
     */
    public YaraCompiler createCompiler() {
        long compiler[] = new long[1];

        int ret = library.yr_compiler_create(compiler);
        if (ret != 0) {
            throw new YaraException(ret);
        }

        return new YaraCompiler(this.library, compiler[0]);
    }

    @Override
    public void close() throws Exception {
        if (library != null) {
            library.yr_finalize();
        }
    }
}
