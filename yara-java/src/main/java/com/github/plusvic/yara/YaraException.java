package com.github.plusvic.yara;

/**
 * Yara exception
 *
 */
public class YaraException extends RuntimeException {
    private int code;

    public YaraException(int code) {
        super(String.format("Code: %d", code));
        this.code = code;
    }

    public YaraException(String message) {
        super(message);
        this.code = ErrorCode.UNKNOWN.getValue();
    }

    public int getNativeCode() {
        return this.code;
    }

    public ErrorCode getCode() {
        return  ErrorCode.from(this.code);
    }
}
