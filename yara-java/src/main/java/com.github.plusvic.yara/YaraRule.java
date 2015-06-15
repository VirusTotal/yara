package com.github.plusvic.yara;

import java.util.Iterator;

/**
 * Yara rule
 *
 */
public interface YaraRule {
    /**
     * Rule identifier
     * @return
     */
    String getIdentifier();

    /**
     * Rule metadata
     * @return
     */
    Iterator<YaraMeta> getMetadata();

    /**
     * Rule strings
     * @return
     */
    Iterator<YaraString> getStrings();
}
