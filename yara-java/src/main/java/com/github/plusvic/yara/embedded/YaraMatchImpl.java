package com.github.plusvic.yara.embedded;

import com.github.plusvic.yara.Preconditions;
import com.github.plusvic.yara.YaraMatch;

/**
 * Yara rule match
 */
public class YaraMatchImpl implements YaraMatch {
    private final YaraLibrary library;
    private final long peer;

    YaraMatchImpl(YaraLibrary library, long peer) {
        Preconditions.checkArgument(library != null);
        Preconditions.checkArgument(peer != 0);

        this.library = library;
        this.peer = peer;
    }

    /**
     * Value that was matched
     * @return
     */
    public String getValue() {
        return library.yara_match_value(null, peer);
    }

    /**
     * Offset where match was found
     * @return
     */
    public long getOffset() {
        return library.yara_match_offset(null, peer);
    }
}
