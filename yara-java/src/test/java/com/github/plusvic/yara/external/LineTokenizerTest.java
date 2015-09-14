package com.github.plusvic.yara.external;

import org.junit.Test;

import java.util.Iterator;

import static org.junit.Assert.*;

/**
 * User: pba
 * Date: 6/15/15
 * Time: 6:15 PM
 */
public class LineTokenizerTest {
    @Test(expected = IllegalArgumentException.class)
    public void testCreateNull() {
        new LineTokenizer(null);
    }

    @Test
    public void testOneString() {
        String test = "single \n\t test";
        String value = "\"single \n\t test\"";

        LineTokenizer tokenizer = new LineTokenizer(value);
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.STRING, test), tokens.next());
        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

    @Test
    public void testOneIdentifier() {
        String value = "single";

        LineTokenizer tokenizer = new LineTokenizer(value);
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, value), tokens.next());
        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

    @Test
    public void testCurrencyIdentifier() {
        String value = "$single";

        LineTokenizer tokenizer = new LineTokenizer(value);
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, value), tokens.next());
        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

    @Test
    public void testOneNumber() {
        String value = "123";

        LineTokenizer tokenizer = new LineTokenizer(value);
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.NUMBER, value), tokens.next());
        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

    @Test
    public void testOneNegativeNumber() {
        String value = "-123";

        LineTokenizer tokenizer = new LineTokenizer(value);
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.NUMBER, value), tokens.next());
        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

    @Test
    public void testOneHexNumber() {
        String value = "0x123";

        LineTokenizer tokenizer = new LineTokenizer(value);
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.NUMBER, value), tokens.next());
        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

    @Test
    public void testOneHexUpperNumber() {
        String value = "0X123";

        LineTokenizer tokenizer = new LineTokenizer(value);
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.NUMBER, value), tokens.next());
        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

    @Test
    public void testOneHexDigitsNumber() {
        String value = "0xABCDEF123";

        LineTokenizer tokenizer = new LineTokenizer(value);
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.NUMBER, value), tokens.next());
        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

    @Test
    public void testWrongHexNumber() {
        String value = "0x1X23";

        LineTokenizer tokenizer = new LineTokenizer(value);
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.NUMBER, "0x1"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "X23"), tokens.next());
        assertFalse(tokens.hasNext());
        assertTrue(tokenizer.hasEnded());
    }

    @Test
    public void testEmpty() {
        String value = "";

        LineTokenizer tokenizer = new LineTokenizer(value);
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.next(LineTokenizer.TokenType.COLON));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

   private void testTerm(LineTokenizer.TokenType type, String value) {
        LineTokenizer tokenizer = new LineTokenizer(value);
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(type, value), tokens.next());
        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

    @Test
    public void testOneColon() {
       testTerm(LineTokenizer.TokenType.COLON, ":");
    }

    @Test
    public void testOneLBracket() {
        testTerm(LineTokenizer.TokenType.LFTSQ_BRACKET, "[");
    }

    @Test
    public void testOneRBracket() {
        testTerm(LineTokenizer.TokenType.RGTSQ_BRACKET, "]");
    }

    @Test
    public void testOneCommaBracket() {
        testTerm(LineTokenizer.TokenType.COMMA, ",");
    }

    @Test
    public void testOneEquals() {
        testTerm(LineTokenizer.TokenType.EQUALS, "=");
    }

    @Test
    public void testTwo() {
        LineTokenizer tokenizer = new LineTokenizer("one:two");
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "one"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.COLON, ":"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "two"), tokens.next());

        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

    @Test
    public void testThreeOneEmpty() {
        LineTokenizer tokenizer = new LineTokenizer("one::two");
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "one"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.COLON, "::"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "two"), tokens.next());

        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

    @Test
    public void testTwoAndEmpty() {
        LineTokenizer tokenizer = new LineTokenizer("one:two:");
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "one"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.COLON, ":"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "two"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.COLON, ":"), tokens.next());

        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

    @Test
    public void testMultiple() {
        LineTokenizer tokenizer = new LineTokenizer("one [two=\"test\",second=\"hello\"]");
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "one"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.LFTSQ_BRACKET, "["), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "two"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.EQUALS, "="), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.STRING, "test"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.COMMA, ","), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "second"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.EQUALS, "="), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.STRING, "hello"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.RGTSQ_BRACKET, "]"), tokens.next());

        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

    @Test
    public void testSkipWhitespace() {
        LineTokenizer tokenizer = new LineTokenizer("one[ two=\"test\",\tsecond=\"hello\"]");
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "one"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.LFTSQ_BRACKET, "["), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "two"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.EQUALS, "="), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.STRING, "test"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.COMMA, ","), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "second"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.EQUALS, "="), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.STRING, "hello"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.RGTSQ_BRACKET, "]"), tokens.next());

        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

    @Test
    public void testIdentifier() {
        LineTokenizer tokenizer = new LineTokenizer("one_ two123 t_h_r123_123");
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "one_"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "two123"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "t_h_r123_123"), tokens.next());

        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

    @Test
    public void testString() {
        LineTokenizer tokenizer = new LineTokenizer("one \"this is a test\" two");
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "one"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.STRING, "this is a test"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "two"), tokens.next());

        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }


    @Test
    public void testUnbalancedString() {
        LineTokenizer tokenizer = new LineTokenizer("one \"this is a test\"\"two");
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "one"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.STRING, "this is a test"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.STRING, "two"), tokens.next());;

        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

    @Test
    public void testEquals() {
        LineTokenizer tokenizer = new LineTokenizer("one = \"this is a test\"");
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "one"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.EQUALS, "="), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.STRING, "this is a test"), tokens.next());

        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

    @Test
    public void testSkipUntilFound() {
        LineTokenizer tokenizer = new LineTokenizer("one = 1, two=\t\"this is a test\"]");

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.RGTSQ_BRACKET, "]"),
                tokenizer.skipUntil(LineTokenizer.TokenType.RGTSQ_BRACKET));
        assertTrue(tokenizer.hasEnded());
    }

    @Test
    public void testSkipUntilNotFound() {
        LineTokenizer tokenizer = new LineTokenizer("one = 1, two=\t\"this is a test\"]");
        assertEquals(LineTokenizer.Token.EMPTY,
                tokenizer.skipUntil(LineTokenizer.TokenType.LFTSQ_BRACKET));
        assertTrue(tokenizer.hasEnded());
    }

    @Test
    public void testNumber() {
        LineTokenizer tokenizer = new LineTokenizer("one = 123");
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "one"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.EQUALS, "="), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.NUMBER, "123"), tokens.next());

        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

    @Test
    public void testNegativeNumber() {
        LineTokenizer tokenizer = new LineTokenizer("one = -321");
        Iterator<LineTokenizer.Token> tokens =  tokenizer.next(LineTokenizer.TOKENS_ALL).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "one"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.EQUALS, "="), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.NUMBER, "-321"), tokens.next());

        assertFalse(tokens.hasNext());
        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
    }

    @Test
    public void testNextUntilFound() {
        LineTokenizer tokenizer = new LineTokenizer("one = 1, two=\t\"this is a test\"]");
        Iterator<LineTokenizer.Token> tokens =  tokenizer.nextUntil(LineTokenizer.TokenType.COMMA).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "one"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.EQUALS, "="), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.NUMBER, "1"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.COMMA, ","), tokens.next());
        assertFalse(tokens.hasNext());

        tokens =  tokenizer.nextUntil(LineTokenizer.TokenType.RGTSQ_BRACKET).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "two"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.EQUALS, "="), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.STRING, "this is a test"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.RGTSQ_BRACKET, "]"), tokens.next());
        assertFalse(tokens.hasNext());

        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
        assertTrue(tokenizer.hasEnded());
    }

    @Test
    public void testNextUntilNotFound() {
        LineTokenizer tokenizer = new LineTokenizer("one = 1,");
        Iterator<LineTokenizer.Token> tokens =  tokenizer.nextUntil(LineTokenizer.TokenType.RGTSQ_BRACKET).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "one"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.EQUALS, "="), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.NUMBER, "1"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.COMMA, ","), tokens.next());
        assertFalse(tokens.hasNext());

        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
        assertTrue(tokenizer.hasEnded());
    }

    @Test
    public void testNextSequenceFound() {
        LineTokenizer tokenizer = new LineTokenizer("one = 1, two=\t\"this is a test\"");
        Iterator<LineTokenizer.Token> tokens =  tokenizer.nextSequence(
                LineTokenizer.TokenType.IDENTIFIER,
                LineTokenizer.TokenType.EQUALS,
                LineTokenizer.TokenType.NUMBER,
                LineTokenizer.TokenType.COMMA,
                LineTokenizer.TokenType.IDENTIFIER,
                LineTokenizer.TokenType.EQUALS,
                LineTokenizer.TokenType.STRING,
                LineTokenizer.TokenType.EMPTY
        ).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "one"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.EQUALS, "="), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.NUMBER, "1"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.COMMA, ","), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "two"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.EQUALS, "="), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.STRING, "this is a test"), tokens.next());
        assertEquals(LineTokenizer.Token.EMPTY, tokens.next());
        assertFalse(tokens.hasNext());

        assertEquals(LineTokenizer.EMPTY_TOKENS, tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertEquals(LineTokenizer.Token.EMPTY, tokenizer.rest());
        assertTrue(tokenizer.hasEnded());
    }

    @Test
    public void testNextSequenceNotFound() {
        LineTokenizer tokenizer = new LineTokenizer("one = \"blabla\", two=-123");
        Iterator<LineTokenizer.Token> tokens =  tokenizer.nextSequence(
                LineTokenizer.TokenType.IDENTIFIER,
                LineTokenizer.TokenType.EQUALS,
                LineTokenizer.TokenType.STRING,
                LineTokenizer.TokenType.COMMA,
                LineTokenizer.TokenType.IDENTIFIER,
                LineTokenizer.TokenType.EQUALS,
                LineTokenizer.TokenType.STRING,
                LineTokenizer.TokenType.EMPTY
        ).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "one"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.EQUALS, "="), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.STRING, "blabla"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.COMMA, ","), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "two"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.EQUALS, "="), tokens.next());
        assertFalse(tokens.hasNext());

        assertFalse(tokenizer.hasEnded());
    }

    @Test
    public void testMatchSequence() {
        LineTokenizer tokenizer = new LineTokenizer("0xf:$a: Hello World");
        Iterator<LineTokenizer.Token> tokens =  tokenizer.nextSequence(
                LineTokenizer.TokenType.NUMBER,
                LineTokenizer.TokenType.COLON,
                LineTokenizer.TokenType.IDENTIFIER,
                LineTokenizer.TokenType.COLON
        ).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.NUMBER, "0xf"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.COLON, ":"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "$a"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.COLON, ":"), tokens.next());
        assertFalse(tokens.hasNext());

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.STRING, "Hello World"), tokenizer.rest());
        assertTrue(tokenizer.hasEnded());
    }

    @Test
    public void testCheckSequenceMatch() {
        LineTokenizer.TokenType[] sequence = new LineTokenizer.TokenType[] {
                LineTokenizer.TokenType.NUMBER,
                LineTokenizer.TokenType.COLON,
                LineTokenizer.TokenType.IDENTIFIER,
                LineTokenizer.TokenType.COLON
        };

        LineTokenizer tokenizer = new LineTokenizer("0xf:$a: Hello World");
        Iterable<LineTokenizer.Token> tokens =  tokenizer.nextSequence(sequence);

        assertTrue(tokenizer.checkSequence(tokens, sequence));

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.STRING, "Hello World"), tokenizer.rest());
        assertTrue(tokenizer.hasEnded());
    }

    @Test
    public void testCheckSequenceNoMatch() {
        LineTokenizer.TokenType[] sequence = new LineTokenizer.TokenType[] {
                LineTokenizer.TokenType.NUMBER,
                LineTokenizer.TokenType.COLON,
                LineTokenizer.TokenType.IDENTIFIER,
                LineTokenizer.TokenType.COLON,
                LineTokenizer.TokenType.LFTSQ_BRACKET
        };

        LineTokenizer tokenizer = new LineTokenizer("0xf:$a: Hello World");
        Iterable<LineTokenizer.Token> tokens =  tokenizer.nextSequence(sequence);

        assertFalse(tokenizer.checkSequence(tokens, sequence));
    }

    @Test
    public void testMatchRule() {
        LineTokenizer tokenizer = new LineTokenizer("HereIsATest [name=\"Here is a test\",description=\"Some description\"]");
        Iterator<LineTokenizer.Token> tokens =  tokenizer.nextSequence(
                LineTokenizer.TokenType.IDENTIFIER,
                LineTokenizer.TokenType.LFTSQ_BRACKET,
                LineTokenizer.TokenType.IDENTIFIER,
                LineTokenizer.TokenType.EQUALS,
                LineTokenizer.TokenType.STRING,
                LineTokenizer.TokenType.COMMA,
                LineTokenizer.TokenType.IDENTIFIER,
                LineTokenizer.TokenType.EQUALS,
                LineTokenizer.TokenType.STRING,
                LineTokenizer.TokenType.RGTSQ_BRACKET
        ).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "HereIsATest"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.LFTSQ_BRACKET, "["), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "name"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.EQUALS, "="), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.STRING, "Here is a test"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.COMMA, ","), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "description"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.EQUALS, "="), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.STRING, "Some description"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.RGTSQ_BRACKET, "]"), tokens.next());
        assertFalse(tokens.hasNext());

        assertTrue(tokenizer.hasEnded());
    }

    @Test
    public void testMatchRuleSequences() {
        LineTokenizer tokenizer = new LineTokenizer("HereIsATest [name=\"Here is a test\",description=\"Some description\"]");

        // Get rule id
        Iterator<LineTokenizer.Token> tokens =  tokenizer.nextSequence(
                LineTokenizer.TokenType.IDENTIFIER,
                LineTokenizer.TokenType.LFTSQ_BRACKET
        ).iterator();

        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.IDENTIFIER, "HereIsATest"), tokens.next());
        assertEquals(new LineTokenizer.Token(LineTokenizer.TokenType.LFTSQ_BRACKET, "["), tokens.next());

        // Get meta
        boolean ended = false;

        while (!ended) {
            tokens = tokenizer.nextUntil(LineTokenizer.TokenType.COMMA, LineTokenizer.TokenType.RGTSQ_BRACKET)
                                                    .iterator();

            assertEquals(LineTokenizer.TokenType.IDENTIFIER, tokens.next().Type);
            assertEquals(LineTokenizer.TokenType.EQUALS, tokens.next().Type);
            assertEquals(LineTokenizer.TokenType.STRING, tokens.next().Type);

            LineTokenizer.Token temp = tokens.next();
            assertTrue(temp.Type == LineTokenizer.TokenType.COMMA || temp.Type == LineTokenizer.TokenType.RGTSQ_BRACKET);

            ended = temp.Type == LineTokenizer.TokenType.RGTSQ_BRACKET ||
                    temp.Type == LineTokenizer.TokenType.EMPTY;
        }

        assertTrue(tokenizer.hasEnded());
    }
}
