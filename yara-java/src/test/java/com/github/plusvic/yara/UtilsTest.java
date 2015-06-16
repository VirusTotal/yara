package com.github.plusvic.yara;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * User: pba
 * Date: 6/16/15
 * Time: 5:17 PM
 */
public class UtilsTest {
    @Test
    public void testUnescapeEmpty() {
        String value = "";
        assertEquals(value, Utils.unescape(value));
    }
    @Test
    public void testUnescapeNull() {
        String value = null;
        assertEquals(value, Utils.unescape(value));
    }
    @Test
    public void testUnescapeClean() {
        String value = "123123 1231ad   112312 1230ipokxlcmzlkdcm928349082fnsdkfnjkshdf";
        assertEquals(value, Utils.unescape(value));
    }

    @Test
    public void testUnescapeSlash() {
        String value = "123\\\\123";
        assertEquals("123\\123", Utils.unescape(value));
    }
    @Test
    public void testUnescapeDoubleQuote() {
        String value = "123\\\"123";
        assertEquals("123\"123", Utils.unescape(value));
    }
    @Test
    public void testUnescapeQuote() {
        String value = "123\\\'123";
        assertEquals("123\'123", Utils.unescape(value));
    }
    @Test
    public void testUnescapeTab() {
        String value = "123\\\t123";
        assertEquals("123\t123", Utils.unescape(value));
    }
    @Test
    public void testUnescapeNewline() {
        String value = "123\\\n123";
        assertEquals("123\n123", Utils.unescape(value));
    }
}
