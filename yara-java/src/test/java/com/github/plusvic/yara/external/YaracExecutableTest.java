package com.github.plusvic.yara.external;

import com.github.plusvic.yara.TestUtils;
import com.github.plusvic.yara.YaraCompilationCallback;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

/**
 * User: pba
 * Date: 6/15/15
 * Time: 3:36 PM
 */
public class YaracExecutableTest {
    @Test
    public void testCreate() {
        new YaracExecutable();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCreateNull() {
        new YaracExecutable(null);
    }

    @Test
    public void testCreateNativeExec() {
        NativeExecutable exec = createNiceMock(NativeExecutable.class);
        expect(exec.load()).andReturn(true).once();
        replay(exec);

        new YaracExecutable(exec);

        verify(exec);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRuleNullNamespace() {
        YaracExecutable exec = new YaracExecutable();
        assertEquals(exec, exec.addRule(null, Paths.get(System.getProperty("java.io.tmpdir"))));
    }


    @Test
    public void testRule() {
        YaracExecutable exec = new YaracExecutable();
        assertEquals(exec, exec.addRule(Paths.get(System.getProperty("java.io.tmpdir"))));
    }

    @Test
    public void testExecuteNoArgs() throws Exception {
        final AtomicBoolean failure = new AtomicBoolean();

        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                failure.set(true);
            }
        };

        Path output = new YaracExecutable().compile(callback);
        assertNotNull(output);
        assertTrue(failure.get());
    }

    @Test
    public void testExecuteOK() throws Exception {
        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                fail();
            }
        };

        Path output = new YaracExecutable()
                                .addRule(TestUtils.getResource("rules/hello.yara"))
                                .addRule(TestUtils.getResource("rules/test.yara"))
                                .compile(callback);
        assertNotNull(output);
        assertTrue(Files.exists(output));
    }

    @Test
    public void testExecuteError() throws Exception {
        final AtomicBoolean failure = new AtomicBoolean();

        YaraCompilationCallback callback = new YaraCompilationCallback() {
            @Override
            public void onError(ErrorLevel errorLevel, String fileName, long lineNumber, String message) {
                assertEquals(ErrorLevel.ERROR, errorLevel);
                assertTrue(fileName.endsWith("error.yara"));
                assertEquals(13, lineNumber);
                assertTrue(message.endsWith("$b\""));
                failure.set(true);
            }
        };

        Path output = new YaracExecutable()
                            .addRule(TestUtils.getResource("rules/error.yara"))
                            .compile(callback);
        assertNotNull(output);
        assertTrue(failure.get());
    }
}
