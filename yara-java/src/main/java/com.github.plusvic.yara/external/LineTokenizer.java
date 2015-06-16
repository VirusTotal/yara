package com.github.plusvic.yara.external;

import com.github.plusvic.yara.Preconditions;

import java.util.*;

/**
 * Line tokenizer
 */
public class LineTokenizer {
    public enum TokenType {
        /**
         * Empty (no) token
         */
        EMPTY,
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

    public static final class Token {
        public static final Token EMPTY = new Token(TokenType.EMPTY, null);

        public final TokenType  Type;
        public final String     Value;

        public Token(TokenType type) {
            this(type, null);
        }

        public Token(TokenType type, String value) {
            this.Type = type;
            this.Value = value;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null) {
                return false;
            }

            if (obj instanceof Token) {
                Token w = (Token)obj;
                return  Objects.equals(w.Type, this.Type) &&
                        Objects.equals(w.Value, this.Value);
            }
            return false;
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

    private static final Set<Character> HEX_DIGITS = new HashSet<>(Arrays.asList(
            'a','A','b','B',
            'c','C','d','D',
            'e','E','f','F')
    );

    /**
     * All separators and whitespaces
     */
    public static final TokenType[] TOKENS_ALL = TokenType.all();
    /**
     * Empty tokens list
     */
    public static final Iterable<Token> EMPTY_TOKENS = Collections.emptyList();

    private int current;
    private String line;
    private Character term;

    public LineTokenizer(String line) {
        this(line, ':');
    }

    public LineTokenizer(String line, Character term) {
        Preconditions.checkArgument(line != null);
        this.line = line;
        this.current = 0;
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

    public Token rest() {
        if (hasEnded()) {
            return Token.EMPTY;
        }

        skip(TokenType.WHITESPACE);

        Token temp = new Token(TokenType.STRING, line.substring(current));
        current = line.length();

        return temp;
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

        boolean hex = false;

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
            }
            else if (hex && HEX_DIGITS.contains(c)) {
                temp.append(c);
            }
            // Hex string
            else if ((c == 'x' || c == 'X') && temp.toString().equals("0")) {
                temp.append(c);
                hex = true;
            }
            else {
                break;
            }

            current++;
        }

        return (temp.length() > 0 ? temp.toString() : null);
    }

    private Token nextInternal(TokenType tokenType, boolean skipWs) {
        if (skipWs && tokenType != TokenType.WHITESPACE) {
            skip(TokenType.WHITESPACE);
        }

        String value = null;

        switch (tokenType) {
            case EMPTY:
                break;
            case IDENTIFIER:
                value = readIdentifier();
               break;
            case WHITESPACE:
                value = readWhitespace();
                break;
            case NUMBER:
                value = readNumber();
                break;
            case EQUALS:
                value = readTerm('=');
                break;
            case STRING:
                value = readString();
                break;
            case COLON:
                value = readTerm(':');
                break;
            case COMMA:
                value = readTerm(',');
                break;
            case LFTSQ_BRACKET:
                value = readTerm('[');
                break;
            case RGTSQ_BRACKET:
                value = readTerm(']');
                break;
            default:
                throw new IllegalArgumentException();
        }

        return (value != null ? new Token(tokenType, value) : Token.EMPTY);
    }

    /**
     * Read next token of type tokenType
     * @param tokenType
     * @return Token value if read, null otherwise
     */
    public Token next(TokenType tokenType) {
        return nextInternal(tokenType, true);
    }

    /**
     * Read any tokens of tokenTypes
     * @param tokenTypes
     * @return All read token types, null otherwise
     */
    public Iterable<Token> next(TokenType...tokenTypes) {
        if (hasEnded()) {
            return Collections.emptyList();
        }

        boolean data;
        List<Token> tokens = new ArrayList<>();

        do {
            data = false;

            for (TokenType tt : tokenTypes) {
                Token temp = nextInternal(tt, true);

                if (temp != null && !temp.equals(Token.EMPTY)) {
                    tokens.add(temp);
                    data = true;
                }
            }
        }
        while (data);

        return tokens;
    }

    /**
     * Read until we find token type
     * @param tokenTypes
     * @return List of tokens including token of type
     */
    public Iterable<Token> nextUntil(TokenType...tokenTypes) {
        TokenType[] types = TokenType.except(tokenTypes);

        List<Token> tokens = new ArrayList<>();

        for (Token t : next(types)) {
            tokens.add(t);
        }

        for (TokenType tt : tokenTypes) {
            Token t = next(tt);
            if (t != null && t.Type.equals(tt)) {
                tokens.add(t);
                break;
            }
        }
        return tokens;
    }

    /**
     * Match sequence of tokens
     * @param sequence
     * @return Maximum sequence matched
     */
    public Iterable<Token> nextSequence(TokenType...sequence) {
        List<Token> tokens = new ArrayList<>();

        for (TokenType tokenType : sequence) {
            if (tokenType == TokenType.EMPTY) {
                tokens.add(Token.EMPTY);
                continue;
            }

            Token token = next(tokenType);
            if (token.equals(Token.EMPTY)) {
                break;
            }

            tokens.add(token);
        }

        return tokens;
    }

    /**
     * Verify sequence matches
     * @param values
     * @param sequence
     * @return
     */
    public boolean checkSequence(Iterable<Token> values, TokenType...sequence) {
        Iterator<Token> tokens = values.iterator();

        try {
            for (TokenType type : sequence) {
                if (!type.equals(tokens.next().Type)) {
                    return false;
                }
            }
        }
        catch (NoSuchElementException e) {
            return false;
        }

        return !tokens.hasNext();
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
    public Token skipUntil(TokenType type) {
        skip(TokenType.except(type));
        return next(type);
    }
}
