package com.github.plusvic.yara.external;

import com.github.plusvic.yara.Preconditions;

import java.util.ArrayList;
import java.util.List;

/**
 * Line tokenizer
 */
public class LineTokenizer {
    public enum TokenType {
        /**
         * Java-like identifier
         */
        IDENTIFIER,
        /**
         * Number
         */
        NUMBER,
        /**
         * Any whitespace
         */
        WHITESPACE,
        /**
         * Read next equals
         */
        EQUALS,
        /**
         * Any balanced quoted string
         */
        STRING,
        /**
         * Colon character
         */
        COLON,
        /**
         * Column character
         */
        COMMA,
        /**
         * Left square bracket
         */
        LFTSQ_BRACKET,
        /**
         * Right square bracket
         */
        RGTSQ_BRACKET;

        /**
         * Return all token types
         * @return
         */
        public static TokenType[] all() {
            return TokenType.values();
        }

        /**
         * Return all except types
         * @param types
         * @return
         */
        public static TokenType[] except(TokenType...types) {
            List<TokenType> temp = new ArrayList<>();

            for (TokenType t : values()) {
                boolean found = false;

                for (TokenType tt : types) {
                    if (t == tt) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    temp.add(t);
                }
            }

            return temp.toArray(new TokenType[]{});
        }
    }

    /**
     * All separators and whitespaces
     */
    public static final TokenType[] TOKENS_NOTIDVAL = TokenType.except(
            TokenType.IDENTIFIER,
            TokenType.STRING,
            TokenType.NUMBER
    );

    /**
     * All separators and whitespaces
     */
    public static final TokenType[] TOKENS_ALL = TokenType.all();

    private int current, last;
    private String line;
    private Character term;

    public LineTokenizer(String line) {
        this(line, ':');
    }

    public LineTokenizer(String line, Character term) {
        Preconditions.checkArgument(line != null);
        this.line = line;
        this.current = 0;
        this.last = 0;
        this.term = term;
    }

    public int length() {
        return line.length();
    }

    public int position() {
        return current;
    }

    public boolean hasEnded() {
        return current >= line.length();
    }

    public String rest() {
        return (current < line.length() ?
                    line.substring(current) :
                    null);
    }

    private String readIdentifier() {
        if (hasEnded()) {
            return null;
        }

        Character c = line.charAt(current);
        if (!Character.isJavaIdentifierStart(c)) {
            return null;
        }


        StringBuffer temp = new StringBuffer();
        temp.append(c);
        current++;

        while (current < line.length()) {
            c = line.charAt(current);

            if (!Character.isJavaIdentifierPart(c)) {
                break;
            }

            temp.append(c);
            current++;
        }

        return (temp.length() > 0 ? temp.toString() : null);
    }

    private String readWhitespace() {
        if (hasEnded()) {
            return null;
        }

        StringBuffer temp = new StringBuffer();

        while (current < line.length()) {
            Character c = line.charAt(current);

            if (!Character.isWhitespace(c)) {
                break;
            }

            temp.append(c);
            current++;
        }

        return (temp.length() > 0 ? temp.toString() : null);
    }

    private String readTerm(Character term) {
        if (hasEnded()) {
            return null;
        }

        StringBuffer temp = new StringBuffer();

        while (current < line.length()) {
            if (term == line.charAt(current)) {
                temp.append(term);
                current++;
            }
            else {
                break;
            }
        }

        return (temp.length() > 0 ? temp.toString() : null);
    }

    private String readString() {
        if (hasEnded()) {
            return null;
        }

        Character c = line.charAt(current);
        if (c != '\"') {
            return null;
        }

        long stack = 1; // Count how many balanced quotes we have

        Character last = null;
        StringBuffer temp = new StringBuffer();
        current++;

        while (current < line.length() && stack > 0) {
            c = line.charAt(current);

            if (c == '\"') {
                if (last != null && last == '\\') {
                    temp.append(c);
                }
                else {
                    stack--;
                }
            }
            else {
                temp.append(c);
            }
            last = c;
            current++;
        }

        return (temp.length() > 0 ? temp.toString() : null);
    }

    private String readNumber() {
        if (hasEnded()) {
            return null;
        }

        Character c = line.charAt(current);
        if (c != '-' && !Character.isDigit(c)) {
            return null;
        }

        StringBuffer temp = new StringBuffer();
        temp.append(c);
        current++;

        while (current < line.length()) {
            c = line.charAt(current);

            if (Character.isDigit(c)) {
                temp.append(c);
                current++;
            }
            else {
                break;
            }
        }

        return (temp.length() > 0 ? temp.toString() : null);
    }

    private String nextInternal(TokenType tokenType, boolean skipWs) {
        if (skipWs && tokenType != TokenType.WHITESPACE) {
            skip(TokenType.WHITESPACE);
        }

        switch (tokenType) {
            case IDENTIFIER:
                return readIdentifier();
            case WHITESPACE:
                return readWhitespace();
            case NUMBER:
                return readNumber();
            case EQUALS:
                return readTerm('=');
            case STRING:
                return readString();
            case COLON:
                return readTerm(':');
            case COMMA:
                return readTerm(',');
            case LFTSQ_BRACKET:
                return readTerm('[');
            case RGTSQ_BRACKET:
                return readTerm(']');
            default:
                throw new IllegalArgumentException();
        }
    }

    /**
     * Read next token of type tokenType
     * @param tokenType
     * @return Token value if read, null otherwise
     */
    public String next(TokenType tokenType) {
        return nextInternal(tokenType, true);
    }

    /**
     * Read any tokens of tokenTypes
     * @param tokenTypes
     * @return All read token types, null otherwise
     */
    public String next(TokenType...tokenTypes) {
        if (hasEnded()) {
            return null;
        }

        boolean data = false;
        StringBuffer buffer = new StringBuffer();


        do {
            data = false;

            for (TokenType tt : tokenTypes) {
                String temp = nextInternal(tt, false);

                if (temp != null) {
                    buffer.append(temp);
                    data = true;
                }
            }
        }
        while (data);

        return (buffer.length() > 0 ? buffer.toString() : null);
    }

    /**
     * Skip token type
     * @param tokenType
     */
    public void skip(TokenType tokenType) {
        next(tokenType);
    }

    /**
     * Skip tokens of types
     * @param tokenTypes
     */
    public void skip(TokenType...tokenTypes) {
        next(tokenTypes);
    }

    /**
     * Skip until token of type is read
     * @param type
     * @return
     */
    public String skipUntil(TokenType type) {
        skip(TokenType.except(type));
        return next(type);
    }
}
