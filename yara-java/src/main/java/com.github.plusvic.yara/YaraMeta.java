package com.github.plusvic.yara;

/**
 * User: pba
 * Date: 6/9/15
 * Time: 3:06 PM
 */
public class YaraMeta {
    public enum Type {
        NULL(0),
        INTEGER(1),
        STRING(2),
        BOOLEAN(3);

        private int value;

        Type(int value) {
            this.value = value;
        }

        public static Type from(int value) {
            for (Type t : Type.values()) {
                if (t.value == value) {
                    return t;
                }
            }

            throw new IllegalArgumentException();
        }
    }

    private final YaraLibrary library;
    private final long peer;

    YaraMeta(YaraLibrary library, long peer) {
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
