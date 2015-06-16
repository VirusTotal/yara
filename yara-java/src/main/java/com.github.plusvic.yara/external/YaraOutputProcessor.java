package com.github.plusvic.yara.external;

import com.github.plusvic.yara.Preconditions;
import com.github.plusvic.yara.Utils;
import com.github.plusvic.yara.YaraScanCallback;

import java.util.Iterator;


class YaraOutputProcessor {
    private YaraScanCallback callback;
    private YaraRuleImpl rule;
    private YaraStringImpl   string;

    public YaraOutputProcessor(YaraScanCallback callback) {
        Preconditions.checkArgument(callback != null);
        this.callback = callback;
    }

    public void onStart() {
    }

    /**
     * Parse output line
     * @param line
     */
    public void onLine(String line) {
        if (!line.startsWith("0x")) {
             onRule(line);
        }
        else {
            onString(line);
        }
    }

    /**
     * Complete parsing
     */
    public void onComplete() {
        if (rule != null) {
            onRuleComplete();
        }
    }

    private static String checkTokenType(LineTokenizer.Token token,LineTokenizer.TokenType type) {
        if (token == null || type == null || !type.equals(token.Type)) {
            throw new IllegalArgumentException();
        }

        return token.Value;
    }

    /**
     * New rule matched
     * @param line
     */
    private void onRule(String line) {
        if (rule != null) {
            onRuleComplete();
        }

        LineTokenizer tokenizer = new LineTokenizer(line);

        // Identifier first, metadata second. Cannot be null or empty and
        String ruleId = checkTokenType(tokenizer.next(LineTokenizer.TokenType.IDENTIFIER),
                                LineTokenizer.TokenType.IDENTIFIER);
        rule = new YaraRuleImpl(ruleId);

        // Move the start of metadata, there should be only one pair of [] since we print
        // only metadata (change this code is for example we start printing tags)
        checkTokenType(tokenizer.next(LineTokenizer.TokenType.LFTSQ_BRACKET),
                LineTokenizer.TokenType.LFTSQ_BRACKET);

        // Now all gets messy because yara does not write the output properly formatted,
        // escaped quotes are printed unescaped so \" becomes " in the output. We expect
        // pairs of id=(number | string | boolean)
        boolean ended = false;

        while (!ended) {
            Iterator<LineTokenizer.Token> tokens = tokenizer.nextUntil(LineTokenizer.TokenType.COMMA,
                                                            LineTokenizer.TokenType.RGTSQ_BRACKET)
                                                        .iterator();

            // Right square bracket when empty
            LineTokenizer.Token temp = tokens.next();
            if (temp.Type == LineTokenizer.TokenType.RGTSQ_BRACKET) {
                break;
            }

            // Skip invalid metadata entries due to formatting errors
            if (temp.Type != LineTokenizer.TokenType.IDENTIFIER) {
                continue;
            }

            // Get meta id when not
            String metaId = temp.Value;
            checkTokenType(tokens.next(), LineTokenizer.TokenType.EQUALS);

            // Get value
            temp = tokens.next();
            switch (temp.Type) {
                case STRING:
                    rule.addMeta(new YaraMetaImpl(metaId, Utils.unescape(temp.Value)));
                    break;
                case NUMBER:
                    rule.addMeta(new YaraMetaImpl(metaId, Integer.decode(temp.Value)));
                    break;
                case IDENTIFIER:
                    rule.addMeta(new YaraMetaImpl(metaId, Boolean.valueOf(temp.Value)));
                    break;
                default:
                    throw new IllegalArgumentException();
            }

            temp = tokens.next();
            ended = (temp.Type == LineTokenizer.TokenType.EMPTY || temp.Type == LineTokenizer.TokenType.RGTSQ_BRACKET);
        }
    }

    /**
     * Rule match completed
     */
    private void onRuleComplete() {
        callback.onMatch(rule);
        rule = null;
        string = null;
    }

    /**
     * New string match
     * @param line
     */
    private void onString(String line) {
        Preconditions.checkState(rule != null);

        LineTokenizer tokenizer = new LineTokenizer(line);

        // Parse string match line
        Iterator<LineTokenizer.Token> tokens = tokenizer.nextSequence(
                LineTokenizer.TokenType.NUMBER,
                LineTokenizer.TokenType.COLON,
                LineTokenizer.TokenType.IDENTIFIER,
                LineTokenizer.TokenType.COLON
        ).iterator();

        String offset     = tokens.next().Value; tokens.next();
        String identifier = tokens.next().Value;tokens.next();
        String value      = tokenizer.rest().Value;

        // Add match to string
        if (string == null || !identifier.equals(string.getIdentifier())) {
            string = new YaraStringImpl(identifier);
            rule.addString(string); // rule should not be null
        }

        string.addMatch(Integer.decode(offset), value);
    }
}
