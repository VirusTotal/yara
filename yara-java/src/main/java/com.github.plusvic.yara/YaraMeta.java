package com.github.plusvic.yara;

/**
 * Yara meta
 */
public interface YaraMeta {
    enum Type {
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

    /**
     * Get metadata type
     * @return
     */
    Type getType();

    /**
     * Get metadata identifier
     * @return
     */
    String getIndentifier();

    /**
     * Get metadata string value
     * @return
     */
    String getString();

    /**
     * Get metadata integer value
     * @return
     */
    int getInteger();
}
