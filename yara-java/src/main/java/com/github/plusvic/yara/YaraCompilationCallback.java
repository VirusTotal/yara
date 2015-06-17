package com.github.plusvic.yara;

/**
 * Compilation callback
 */
public interface YaraCompilationCallback {
    /**
     * Compilation error level
     */
    public enum ErrorLevel {
        ERROR(0),
        WARNING(1);

        private int value;

        ErrorLevel(int value) {
            this.value = value;
        }

        public static ErrorLevel from(int value) {
            for (ErrorLevel t : ErrorLevel.values()) {
                if (t.value == value) {
                    return t;
                }
            }

            throw new IllegalArgumentException();
        }
    }

    /**
     * Compilation error occured
     * @param errorLevel    Error level
     * @param fileName      File name being compiled (empty if string)
     * @param lineNumber    Line number
     * @param message       Error message
     */
    void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message);
}
