package com.github.plusvic.yara.embedded;

import com.github.plusvic.yara.*;

import java.util.Iterator;

/**
 * Yara rule
 */
public class YaraRuleImpl implements YaraRule {
    private final YaraLibrary library;
    private final long    peer;

    YaraRuleImpl(YaraLibrary library, long peer) {
        Preconditions.checkArgument(library != null);
        Preconditions.checkArgument(peer != 0);

        this.library = library;
        this.peer = peer;
    }

    /**
     * Rule identifier
     * @return
     */
    public String getIdentifier() {
        return library.yara_rule_identifier(null, peer);
    }

    /**
     * Rule metadata
     * @return
     */
    public Iterator<YaraMeta> getMetadata() {
        return new GenericIterator<YaraMeta>() {
            private long index = library.yara_rule_metas(null, peer);

            @Override
            protected YaraMetaImpl getNext() {
                long last = index;
                index = library.yara_rule_meta_next(null, index);

                if (index == 0 || last == 0) {
                    return null;
                }

                return new YaraMetaImpl(library, last);
            }
        };
    }

    /**
     * Rule strings
     * @return
     */
    public Iterator<YaraString> getStrings() {
        return new GenericIterator<YaraString>() {
            private long index = library.yara_rule_strings(null, peer);

            @Override
            protected YaraStringImpl getNext() {
                long last = index;
                index = library.yara_rule_string_next(null, index);

                if (index == 0 || last == 0) {
                    return null;
                }

                return new YaraStringImpl(library, last);
            }
        };
    }
}
