package com.github.plusvic.yara.external;

import org.junit.Test;

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
    public void testOne() {
        String value = "single  \n test";

        LineTokenizer tokenizer = new LineTokenizer(value);
        assertEquals(value, tokenizer.next(LineTokenizer.TokenType.IDENTIFIER, LineTokenizer.TokenType.WHITESPACE));
        assertNull(tokenizer.next());
        assertNull(tokenizer.rest());
    }
    @Test
    public void testEmpty() {
        String value = "";

        LineTokenizer tokenizer = new LineTokenizer(value);
        assertNull(tokenizer.next(LineTokenizer.TokenType.COLON));
        assertNull(tokenizer.rest());
    }
    @Test
    public void testOneEmpty() {
        String value = ":";

        LineTokenizer tokenizer = new LineTokenizer(value);
        assertEquals(":", tokenizer.next(LineTokenizer.TokenType.COLON));
        assertNull(tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertNull(tokenizer.rest());
    }

    @Test
    public void testTwo() {
        LineTokenizer tokenizer = new LineTokenizer("one:two");
        assertEquals("one", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        tokenizer.skip(LineTokenizer.TokenType.COLON);
        assertEquals("two", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        assertNull(tokenizer.next());
        assertNull(tokenizer.rest());
    }

    @Test
    public void testThreeOneEmpty() {
        LineTokenizer tokenizer = new LineTokenizer("one::two");
        assertEquals("one", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        assertEquals("::", tokenizer.next(LineTokenizer.TokenType.COLON));
        assertEquals("two", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        assertNull(tokenizer.next(LineTokenizer.TOKENS_ALL));
        assertNull(tokenizer.rest());
    }

    @Test
    public void testTwoAndEmpty() {
        LineTokenizer tokenizer = new LineTokenizer("one:two:");
        assertEquals("one", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        assertNotNull(tokenizer.next(LineTokenizer.TokenType.COLON));
        assertEquals("two", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        assertNotNull(tokenizer.next(LineTokenizer.TokenType.COLON));
        assertNull(tokenizer.next(LineTokenizer.TokenType.COLON));
        assertNull(tokenizer.rest());
    }

    @Test
    public void testMultiple() {
        LineTokenizer tokenizer = new LineTokenizer("one [two=\"test\",second=\"hello\"]");
        assertEquals("one", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        tokenizer.skip(LineTokenizer.TokenType.WHITESPACE);
        assertNotNull(tokenizer.next(LineTokenizer.TokenType.LFTSQ_BRACKET));
        assertEquals("two", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        tokenizer.skip(LineTokenizer.TokenType.EQUALS);
        assertEquals("test", tokenizer.next(LineTokenizer.TokenType.STRING));
        tokenizer.skip(LineTokenizer.TokenType.COMMA);
        assertEquals("second", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        tokenizer.skip(LineTokenizer.TokenType.EQUALS);
        assertEquals("hello", tokenizer.next(LineTokenizer.TokenType.STRING));
        tokenizer.skip(LineTokenizer.TokenType.RGTSQ_BRACKET);
        assertNull(tokenizer.next());
        assertNull(tokenizer.rest());
    }

    @Test
    public void testSkipWhitespace() {
        LineTokenizer tokenizer = new LineTokenizer("one[ two=\"test\",\tsecond=\"hello\"]");
        assertEquals("one", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        tokenizer.skip(LineTokenizer.TOKENS_NOTIDVAL);
        assertEquals("two", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        tokenizer.skip(LineTokenizer.TOKENS_NOTIDVAL);
        assertEquals("test", tokenizer.next(LineTokenizer.TokenType.STRING));
        tokenizer.skip(LineTokenizer.TOKENS_NOTIDVAL);
        assertEquals("second", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        tokenizer.skip(LineTokenizer.TOKENS_NOTIDVAL);
        assertEquals("hello", tokenizer.next(LineTokenizer.TokenType.STRING));
        assertEquals("]", tokenizer.next(LineTokenizer.TokenType.RGTSQ_BRACKET));
        assertNull(tokenizer.next(LineTokenizer.TokenType.COLON));
        assertNull(tokenizer.rest());
    }

    @Test
    public void testIdentifier() {
        LineTokenizer tokenizer = new LineTokenizer("one_ two123 t_h_r123_123");
        assertEquals("one_", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        assertEquals("two123", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        assertEquals("t_h_r123_123", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        assertNull(tokenizer.next());
        assertNull(tokenizer.rest());
    }

    @Test
    public void testString() {
        LineTokenizer tokenizer = new LineTokenizer("one \"this is a test\" two");
        assertEquals("one", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        assertEquals("this is a test", tokenizer.next(LineTokenizer.TokenType.STRING));
        assertEquals("two", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        assertTrue(tokenizer.hasEnded());
    }


    @Test
    public void testUnbalancedString() {
        LineTokenizer tokenizer = new LineTokenizer("one \"this is a test\"\"two");
        assertEquals("one", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        assertEquals("this is a test", tokenizer.next(LineTokenizer.TokenType.STRING));
        assertEquals("two", tokenizer.next(LineTokenizer.TokenType.STRING));
        assertTrue(tokenizer.hasEnded());
    }

    @Test
    public void testEquals() {
        LineTokenizer tokenizer = new LineTokenizer("one = \"this is a test\"");
        assertEquals("one", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        tokenizer.skip(LineTokenizer.TOKENS_NOTIDVAL);
        assertEquals("this is a test", tokenizer.next(LineTokenizer.TokenType.STRING));
        assertTrue(tokenizer.hasEnded());
    }

    @Test
    public void testSkipUntilFound() {
        LineTokenizer tokenizer = new LineTokenizer("one = 1, two=\t\"this is a test\"]");
        assertEquals("]", tokenizer.skipUntil(LineTokenizer.TokenType.RGTSQ_BRACKET));
        assertTrue(tokenizer.hasEnded());
    }

    @Test
    public void testSkipUntilNotFound() {
        LineTokenizer tokenizer = new LineTokenizer("one = 1, two=\t\"this is a test\"]");
        assertEquals(null, tokenizer.skipUntil(LineTokenizer.TokenType.LFTSQ_BRACKET));
        assertTrue(tokenizer.hasEnded());
    }

    @Test
    public void testNumber() {
        LineTokenizer tokenizer = new LineTokenizer("one = 123");
        assertEquals("one", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        tokenizer.skip(LineTokenizer.TOKENS_NOTIDVAL);
        assertEquals(123, (int)Integer.valueOf(tokenizer.next(LineTokenizer.TokenType.NUMBER)));
        assertTrue(tokenizer.hasEnded());
    }

    @Test
    public void testNegativeNumber() {
        LineTokenizer tokenizer = new LineTokenizer("one = -321");
        assertEquals("one", tokenizer.next(LineTokenizer.TokenType.IDENTIFIER));
        tokenizer.skip(LineTokenizer.TOKENS_NOTIDVAL);
        assertEquals(-321, (int)Integer.valueOf(tokenizer.next(LineTokenizer.TokenType.NUMBER)));
        assertTrue(tokenizer.hasEnded());
    }
}
