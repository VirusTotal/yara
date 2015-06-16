package com.github.plusvic.yara.external;

import com.github.plusvic.yara.*;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.easymock.EasyMock.createNiceMock;
import static org.junit.Assert.*;

/**
 * User: pba
 * Date: 6/16/15
 * Time: 3:56 PM
 */
public class YaraOutputProcessorTest {
    @Test(expected = IllegalArgumentException.class)
    public void testCreateNull() {
        new YaraOutputProcessor(null);
    }

    @Test
    public void testCreate() {
        new YaraOutputProcessor(createNiceMock(YaraScanCallback.class));
    }

    @Test
    public void testStartComplete() {
        YaraScanCallback callback = new YaraScanCallback() {
            @Override
            public void onMatch(YaraRule rule) {
                fail();
            }
        };

        YaraOutputProcessor processor = new YaraOutputProcessor(callback);
        processor.onStart();
        processor.onComplete();
    }

    @Test
    public void testRuleNoMeta() {
        final AtomicReference<YaraRule> captureRule = new AtomicReference<>();

        YaraScanCallback callback = new YaraScanCallback() {
            @Override
            public void onMatch(YaraRule rule) {
                captureRule.set(rule);
            }
        };

        String value = "HelloWorld []";

        YaraOutputProcessor processor = new YaraOutputProcessor(callback);
        processor.onStart();
        processor.onLine(value);
        processor.onComplete();

        assertNotNull(captureRule.get());
        assertEquals("HelloWorld", captureRule.get().getIdentifier());
        assertFalse(captureRule.get().getMetadata().hasNext());
        assertFalse(captureRule.get().getStrings().hasNext());
    }

    @Test
    public void testRuleMeta() {
        final AtomicReference<YaraRule> captureRule = new AtomicReference<>();

        YaraScanCallback callback = new YaraScanCallback() {
            @Override
            public void onMatch(YaraRule rule) {
                captureRule.set(rule);
            }
        };

        String value = "HelloWorld [name=\"InstallsDriver\",description=\"The file attempted to install a driver\"]";

        YaraOutputProcessor processor = new YaraOutputProcessor(callback);
        processor.onStart();
        processor.onLine(value);
        processor.onComplete();

        YaraRule rule = captureRule.get();

        assertNotNull(rule);
        assertEquals("HelloWorld", rule.getIdentifier());
        assertFalse(rule.getStrings().hasNext());

        Iterator<YaraMeta> metas = rule.getMetadata();

        YaraMeta meta = metas.next();
        assertEquals("name", meta.getIndentifier());
        assertEquals("InstallsDriver", meta.getString());

        meta = metas.next();
        assertEquals("description", meta.getIndentifier());
        assertEquals("The file attempted to install a driver", meta.getString());

        assertFalse(metas.hasNext());
    }

    @Test
    public void testRuleMetaAll() {
        final AtomicReference<YaraRule> captureRule = new AtomicReference<>();

        YaraScanCallback callback = new YaraScanCallback() {
            @Override
            public void onMatch(YaraRule rule) {
                captureRule.set(rule);
            }
        };

        String value = "HelloWorld [string=\"String\",number=1,boolean=true]";

        YaraOutputProcessor processor = new YaraOutputProcessor(callback);
        processor.onStart();
        processor.onLine(value);
        processor.onComplete();

        YaraRule rule = captureRule.get();

        assertNotNull(rule);
        assertEquals("HelloWorld", rule.getIdentifier());
        assertFalse(rule.getStrings().hasNext());

        Iterator<YaraMeta> metas = rule.getMetadata();

        YaraMeta meta = metas.next();
        assertEquals("string", meta.getIndentifier());
        assertEquals("String", meta.getString());

        meta = metas.next();
        assertEquals("number", meta.getIndentifier());
        assertEquals(1, meta.getInteger());

        meta = metas.next();
        assertEquals("boolean", meta.getIndentifier());
        assertEquals(1, meta.getInteger());

        assertFalse(metas.hasNext());
    }

    @Test
    public void testRuleMetaUgly() {
        final AtomicReference<YaraRule> captureRule = new AtomicReference<>();

        YaraScanCallback callback = new YaraScanCallback() {
            @Override
            public void onMatch(YaraRule rule) {
                captureRule.set(rule);
            }
        };

        String value = "HelloWorld [name=\"InstallsDriver\"," +
                "description=\"The file attempted to install a driver\"," +
                "categories=\"Process \\\",= Creation\"," +
                "type=\"external\"," +
                "behaviors=\"InstallsDriver\"," +
                "output=\"([^\\\"]*)$\"," +
                "template=\"%s\"] test.bla";

        YaraOutputProcessor processor = new YaraOutputProcessor(callback);
        processor.onStart();
        processor.onLine(value);
        processor.onComplete();

        YaraRule rule = captureRule.get();

        assertNotNull(rule);
        assertEquals("HelloWorld", rule.getIdentifier());
        assertFalse(rule.getStrings().hasNext());

        Iterator<YaraMeta> metas = rule.getMetadata();

        YaraMeta meta = metas.next();
        assertEquals("name", meta.getIndentifier());
        assertEquals("InstallsDriver", meta.getString());

        meta = metas.next();
        assertEquals("description", meta.getIndentifier());
        assertEquals("The file attempted to install a driver", meta.getString());

        meta = metas.next();
        assertEquals("categories", meta.getIndentifier());
        assertEquals("Process \",= Creation", meta.getString());

        meta = metas.next();
        assertEquals("type", meta.getIndentifier());
        assertEquals("external", meta.getString());

        meta = metas.next();
        assertEquals("behaviors", meta.getIndentifier());
        assertEquals("InstallsDriver", meta.getString());

        meta = metas.next();
        assertEquals("output", meta.getIndentifier());
        assertEquals("([^\"]*)$", meta.getString());

        meta = metas.next();
        assertEquals("template", meta.getIndentifier());
        assertEquals("%s", meta.getString());

        assertFalse(metas.hasNext());
    }

    @Test
    public void testRuleMultiple() {
        final List<YaraRule> rules =new ArrayList<>();

        YaraScanCallback callback = new YaraScanCallback() {
            @Override
            public void onMatch(YaraRule rule) {
                rules.add(rule);
            }
        };

        String[] lines = new String[] {
                "HelloWorld [name=\"InstallsDriver\",description=\"The file attempted to install a driver\"] test.bla",
                "0xf:$a: Hello World",
                "0x59:$a: Hello World",
                "HereIsATest [internal=true,value=123] test.bla",
                "0x20:$a: here",
                "0x52:$a: here"
        };

        YaraOutputProcessor processor = new YaraOutputProcessor(callback);
        processor.onStart();
        for (String line : lines) {
            processor.onLine(line);
        }
        processor.onComplete();

        assertEquals(2, rules.size());

        // HelloWorld rule
        YaraRule rule = rules.get(0);
        assertNotNull(rule);
        assertEquals("HelloWorld", rule.getIdentifier());

        // Hello world metas
        Iterator<YaraMeta> metas = rule.getMetadata();
        YaraMeta meta = metas.next();
        assertEquals("name", meta.getIndentifier());
        assertEquals("InstallsDriver", meta.getString());

        meta = metas.next();
        assertEquals("description", meta.getIndentifier());
        assertEquals("The file attempted to install a driver", meta.getString());

        // Hello world matches
        Iterator<YaraString> strings = rule.getStrings();
        YaraString string = strings.next();
        assertEquals("$a", string.getIdentifier());

        Iterator<YaraMatch> matches = string.getMatches();
        YaraMatch match = matches.next();
        assertEquals((long)Long.decode("0xf"), match.getOffset());
        assertEquals("Hello World", match.getValue());

        match = matches.next();
        assertEquals((long)Long.decode("0x59"), match.getOffset());
        assertEquals("Hello World", match.getValue());

        assertFalse(metas.hasNext());

        // Hereisatest rule
        rule = rules.get(1);
        assertNotNull(rule);
        assertEquals("HereIsATest", rule.getIdentifier());

        // Hereisatest  metas
        metas = rule.getMetadata();
        meta = metas.next();
        assertEquals("internal", meta.getIndentifier());
        assertEquals(1, meta.getInteger());

        meta = metas.next();
        assertEquals("value", meta.getIndentifier());
        assertEquals(123, meta.getInteger());

        // Hereisatest matches
        strings = rule.getStrings();
        string = strings.next();
        assertEquals("$a", string.getIdentifier());

        matches = string.getMatches();
        match = matches.next();
        assertEquals((long)Long.decode("0x20"), match.getOffset());
        assertEquals("here", match.getValue());

        match = matches.next();
        assertEquals((long)Long.decode("0x52"), match.getOffset());
        assertEquals("here", match.getValue());

        assertFalse(metas.hasNext());
    }
}
