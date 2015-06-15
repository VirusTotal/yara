package com.github.plusvic.yara;

import com.github.plusvic.yara.embedded.YaraRuleImpl;

/**
 * Yara scan callback interface
 */
public interface YaraScanCallback {
    /**
     * Called when a rule matches
     * @param rule Rule that matched
     */
    void onMatch(YaraRuleImpl rule);
}
