package com.github.plusvic.yara;

/**
 * Yara scan callback interface
 */
public interface YaraScanCallback {
    /**
     * Called when a rule matches
     * @param rule Rule that matched
     */
    void onMatch(YaraRule rule);
}
