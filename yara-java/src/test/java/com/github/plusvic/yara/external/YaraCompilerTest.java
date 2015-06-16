package com.github.plusvic.yara.external;

import com.github.plusvic.yara.YaraCompilationCallback;
import com.github.plusvic.yara.YaraCompiler;
import com.github.plusvic.yara.YaraException;
import com.github.plusvic.yara.YaraScanner;
import org.junit.Test;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.Assert.*;

/**
 * User: pba
 * Date: 6/16/15
 * Time: 6:12 PM
 */
public class YaraCompilerTest {
    private final static Logger LOGGER = Logger.getLogger(YaraCompilerTest.class.getName());

    private static final String YARA_RULE_HELLO = "rule HelloWorld\n"+
            "{\n"+
            "\tstrings:\n"+
            "\t\t$a = \"Hello world\"\n"+
            "\n"+
            "\tcondition:\n"+
            "\t\t$a\n"+
            "}";

    private static final String YARA_RULE_NOOP = "rule Noop\n"+
            "{\n"+
            "\tstrings:\n"+
            "\t\t$a = \"\"\n"+
            "\n"+
            "\tcondition:\n"+
            "\t\t$a\n"+
            "}";

    private static final String YARA_RULE_FAIL = "rule HelloWorld\n"+
            "{\n"+
            "\tstrings:\n"+
            "\t\t$a = \"Hello world\"\n"+
            "\n"+
            "\tcondition:\n"+
            "\t\t$a or $b\n"+
            "}";

    @Test
    public void testCreate() {
        new YaraCompilerImpl();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSetNullCallback() {
         new YaraCompilerImpl().setCallback(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testAddNullRule() {
        new YaraCompilerImpl().addRules(null, null);
    }

    @Test
    public void testSetCallback() throws Exception {
        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(new YaraCompilationCallback() {
                @Override
                public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                }
            });
        }
    }

    @Test
    public void testAddRulesSucceeds() throws Exception {
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };

        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRules(YARA_RULE_HELLO, null);
        }
    }

    @Test
    public void testAddRulesFails() throws Exception {
        final AtomicBoolean called = new AtomicBoolean();
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                called.set(true);
                LOGGER.log(Level.INFO, String.format("Compilation failed in %s at %d: %s",
                        fileName, lineNumber, message));
            }
        };

        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRules(YARA_RULE_FAIL, null);

            try {
                assertNotNull(compiler.createScanner());
            }
            catch (YaraException ye) {
            }
        }

        assertTrue(called.get());
    }


    @Test
    public void testCreateScanner() throws Exception {
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };

        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRules(YARA_RULE_HELLO, null);

            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);
            }
        }
    }

    @Test
    public void testAddRulesAfterScannerCreate() throws Exception {
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };

        try (YaraCompiler compiler = new YaraCompilerImpl()) {
            compiler.setCallback(callback);
            compiler.addRules(YARA_RULE_HELLO, null);

            // Get scanner
            try (YaraScanner scanner = compiler.createScanner()) {
                assertNotNull(scanner);
            }

            // Subsequent add rule should fail
            try {
                compiler.addRules(YARA_RULE_NOOP, null);
            }
            catch (YaraException e) {
                assertEquals(1L, e.getNativeCode());
            }
        }
    }

}
