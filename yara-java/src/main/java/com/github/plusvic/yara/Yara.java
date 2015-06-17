package com.github.plusvic.yara;

/**
 * Yara wrapper
 *
 */
public interface Yara extends  AutoCloseable {
    YaraCompiler    createCompiler();
}
