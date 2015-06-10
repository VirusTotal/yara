package com.github.plusvic.yara;

import java.util.Iterator;

/**
 * Yara rule strings
 *
 */
public class YaraString {
    private final YaraLibrary library;
    private final long    peer;

    YaraString(YaraLibrary library, long peer) {
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
            protected YaraMatch getNext() {
                if (index == 0) {
                    return null;
                }

                long last = index;
                index = library.yara_string_match_next(null, index);

                return new YaraMatch(library, last);
            }
        };
    }
}
