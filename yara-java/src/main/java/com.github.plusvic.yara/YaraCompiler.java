package com.github.plusvic.yara;

/**
 *  Yara compiler
 **/
public interface YaraCompiler  extends AutoCloseable {
    /**
     * Set compilation callback
     * @param cbk
     */
    void setCallback(YaraCompilationCallback cbk);

    /**
     * Add rules content
     * @param content
     * @param namespace
     * @return
     */
    boolean addRules(String content, String namespace);

    /**
     * Create scanner
     * @return
     */
    YaraScanner createScanner();
}
