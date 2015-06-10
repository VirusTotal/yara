package com.github.plusvic.yara;

import org.junit.Test;

import static org.junit.Assert.assertNotNull;

/**
 * User: pba
 * Date: 6/9/15
 * Time: 6:51 PM
 */
public class YaraTest {
    @Test
    public void testCreateClose() throws Exception {
        try (Yara yara = new Yara()) {
        }
    }

    @Test
    public void testCreateCompiler() throws Exception {
        try (Yara yara = new Yara()) {
            try (YaraCompiler compiler = yara.createCompiler())  {
                assertNotNull(compiler);
            }
        }
    }
}
