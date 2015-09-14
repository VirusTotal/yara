package com.github.plusvic.yara;

import java.io.File;

/**
 * Yara scanner
 *
 */
public interface YaraScanner extends AutoCloseable {
    /**
     * Set scan timeout
     */
    void setTimeout(int timeout);

    /**
     * Set scan callback
     * @param cbk
     */
    void setCallback(YaraScanCallback cbk);

    /**
     * Scan file
     * @param file
     */
    void scan(File file);
}
