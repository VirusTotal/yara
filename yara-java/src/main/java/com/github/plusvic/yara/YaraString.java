package com.github.plusvic.yara;

import java.util.Iterator;

/**
 * Yara string interface
 *
 */
public interface YaraString {
    /**
     * Get identifier
     * @return
     */
    String getIdentifier();

    /**
     * Get matches for the string
     * @return
     */
    Iterator<YaraMatch> getMatches();
}
