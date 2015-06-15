package com.github.plusvic.yara.embedded;

import com.github.plusvic.yara.GenericIterator;
import com.github.plusvic.yara.Preconditions;
import com.github.plusvic.yara.YaraMatch;
import com.github.plusvic.yara.YaraString;

import java.util.Iterator;

/**
 * Yara rule strings
 *
 */
public class YaraStringImpl implements YaraString {
    private final YaraLibrary library;
    private final long    peer;

    YaraStringImpl(YaraLibrary library, long peer) {
        Preconditions.checkArgument(library != null);
        Preconditions.checkArgument(peer != 0);

        this.library = library;
        this.peer = peer;
    }

    /**
     * Get identifier
     * @return
     */
    public String getIdentifier() {
        return library.yara_string_identifier(null, peer);
    }

    /**
     * Get matches for the string
     * @return
     */
    public Iterator<YaraMatch> getMatches() {
        return new GenericIterator<YaraMatch>() {
            private long index = library.yara_string_matches(null, peer);

            @Override
            protected YaraMatchImpl getNext() {
                if (index == 0) {
                    return null;
                }

                long last = index;
                index = library.yara_string_match_next(null, index);

                return new YaraMatchImpl(library, last);
            }
        };
    }
}
