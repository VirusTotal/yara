package com.github.plusvic.yara.embedded;

import com.github.plusvic.yara.Preconditions;
import com.github.plusvic.yara.YaraMeta;

/**
 * User: pba
 * Date: 6/9/15
 * Time: 3:06 PM
 */
public class YaraMetaImpl implements YaraMeta {


    private final YaraLibrary library;
    private final long peer;

    YaraMetaImpl(YaraLibrary library, long peer) {
        Preconditions.checkArgument(library != null);
        Preconditions.checkArgument(peer != 0);

        this.library = library;
        this.peer = peer;
    }

    public Type getType() {
        return Type.from(library.yara_meta_type(null, peer));
    }

    public String getIndentifier() {
        return library.yara_meta_identifier(null, peer);
    }

    public String getString() {
        return library.yara_meta_string(null, peer);
    }

    public int getInteger() {
        return library.yara_meta_integer(null, peer);
    }
}
