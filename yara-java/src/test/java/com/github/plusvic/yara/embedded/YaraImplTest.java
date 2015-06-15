package com.github.plusvic.yara.embedded;

import org.junit.Test;
import com.github.plusvic.yara.YaraCompiler;

import static org.junit.Assert.assertNotNull;

/**
 * User: pba
 * Date: 6/9/15
 * Time: 6:51 PM
 */
public class YaraImplTest {
    @Test
    public void testCreateClose() throws Exception {
        try (YaraImpl yara = new YaraImpl()) {
        }
    }

    @Test
    public void testCreateCompiler() throws Exception {
        try (YaraImpl yara = new YaraImpl()) {
            try (YaraCompiler compiler = yara.createCompiler())  {
                assertNotNull(compiler);
            }
        }
    }
}
