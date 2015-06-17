package com.github.plusvic.yara;


/**
 * Yara error codes
 */
public enum ErrorCode {
    UNKNOWN(-1),
    SUCCESS(0),
    INSUFICIENT_MEMORY(1),
    COULD_NOT_ATTACH_TO_PROCESS(2),
    COULD_NOT_OPEN_FILE(3),
    COULD_NOT_MAP_FILE(4),
    INVALID_FILE(6),
    CORRUPT_FILE(7),
    UNSUPPORTED_FILE_VERSION(8),
    INVALID_REGULAR_EXPRESSION(9),
    INVALID_HEX_STRING(10),
    SYNTAX_ERROR(11),
    LOOP_NESTING_LIMIT_EXCEEDED(12),
    DUPLICATED_LOOP_IDENTIFIER(13),
    DUPLICATED_IDENTIFIER(14),
    DUPLICATED_TAG_IDENTIFIER(15),
    DUPLICATED_META_IDENTIFIER(16),
    DUPLICATED_STRING_IDENTIFIER(17),
    UNREFERENCED_STRING(18),
    UNDEFINED_STRING(19),
    UNDEFINED_IDENTIFIER(20),
    MISPLACED_ANONYMOUS_STRING(21),
    INCLUDES_CIRCULAR_REFERENCE(22),
    INCLUDE_DEPTH_EXCEEDED(23),
    WRONG_TYPE(24),
    EXEC_STACK_OVERFLOW(25),
    SCAN_TIMEOUT(26),
    TOO_MANY_SCAN_THREADS(27),
    CALLBACK_ERROR(28),
    INVALID_ARGUMENT(29),
    TOO_MANY_MATCHES(30),
    INTERNAL_FATAL_ERROR(31),
    NESTED_FOR_OF_LOOP(32),
    INVALID_FIELD_NAME(33),
    UNKNOWN_MODULE(34),
    NOT_A_STRUCTURE(35),
    NOT_INDEXABLE(36),
    NOT_A_FUNCTION(37),
    INVALID_FORMAT(38),
    TOO_MANY_ARGUMENTS(39),
    WRONG_ARGUMENTS(40),
    WRONG_RETURN_TYPE(41),
    DUPLICATED_STRUCTURE_MEMBER(42);

    private int value;

    ErrorCode(int value) {
        this.value = value;
    }

    public static ErrorCode from(int value) {
        for (ErrorCode t : ErrorCode.values()) {
            if (t.value == value) {
                return t;
            }
        }

        return UNKNOWN;
    }

    public static boolean isSuccess(int code) {
        return code == SUCCESS.value;
    }

    public int getValue() {
        return value;
    }
}
