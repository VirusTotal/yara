package com.github.plusvic.yara;

import org.junit.Test;

import java.util.NoSuchElementException;
import java.util.UUID;

import static org.junit.Assert.*;

/**
 * User: pba
 * Date: 6/12/15
 * Time: 10:43 AM
 */
public class GenericIteratorTest {
    @Test
    public void testEmpty() {
        GenericIterator<String> it = new GenericIterator<String>() {
            @Override
            protected String getNext() {
                return null;
            }
        };
        assertFalse(it.hasNext());
    }

    @Test
    public void testOne() {
        GenericIterator<String> it = new GenericIterator<String>() {
            private boolean used = false;

            @Override
            protected String getNext() {
                if (!used) {
                    used = true;
                    return UUID.randomUUID().toString();
                }
                return null;
            }
        };
        assertTrue(it.hasNext());
        assertNotNull(it.next());
        assertFalse(it.hasNext());
    }

    @Test
    public void testTwo() {
        GenericIterator<String> it = new GenericIterator<String>() {
            private String values[] = new String[] { "one", "two"};
            private int pos = 0;

            @Override
            protected String getNext() {
                if (pos  < values.length) {
                    return values[pos++];
                }
                return null;
            }
        };

        assertTrue(it.hasNext());
        assertNotNull(it.next());
        assertTrue(it.hasNext());
        assertNotNull(it.next());
        assertFalse(it.hasNext());
    }

    @Test
    public void testN() {
        final int size = 10;

        GenericIterator<String> it = new GenericIterator<String>() {
            private String values[];
            private int pos = 0;

            @Override
            protected String getNext() {
                if (values == null) {
                    values = new String[size];
                    for (int i = 0; i < size; ++i) {
                        values[i] = UUID.randomUUID().toString();
                    }
                }
                if (pos  < values.length) {
                    return values[pos++];
                }
                return null;
            }
        };

        int count = 0;
        while (it.hasNext()) {
            count++;
            assertNotNull(it.next());
        }

        assertEquals(size, count);
    }

    @Test(expected = NoSuchElementException.class)
    public void testNextFirst() {
        GenericIterator<String> it = new GenericIterator<String>() {
            private boolean used = false;

            @Override
            protected String getNext() {
                if (!used) {
                    used = true;
                    return UUID.randomUUID().toString();
                }
                return null;
            }
        };

        assertNotNull(it.next());
        assertNotNull(it.next());
    }

    @Test
    public void testNextFirstMultiple() {
        GenericIterator<String> it = new GenericIterator<String>() {
            private String values[] = new String[] { "one", "two"};
            private int pos = 0;

            @Override
            protected String getNext() {
                if (pos  < values.length) {
                    return values[pos++];
                }
                return null;
            }
        };

        assertNotNull(it.next());
        assertNotNull(it.next());
        assertFalse(it.hasNext());
    }
}
