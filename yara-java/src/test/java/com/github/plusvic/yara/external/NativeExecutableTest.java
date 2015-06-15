package com.github.plusvic.yara.external;

import org.junit.Test;

import java.util.UUID;

import static org.junit.Assert.*;

/**
 * User: pba
 * Date: 6/13/15
 * Time: 8:55 AM
 */
public class NativeExecutableTest {
    @Test(expected = IllegalArgumentException.class)
    public void testCreateNoName() {
        new NativeExecutable("");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCreateNullName() {
        new NativeExecutable(null, NativeExecutableTest.class.getClassLoader());
    }

    @Test
    public void testCreate() {
        new NativeExecutable("yara");
    }

    @Test
    public void testLoadNotFound() {
        NativeExecutable exe = new NativeExecutable(UUID.randomUUID().toString());
        assertFalse(exe.load());
    }

    @Test
    public void testLoadYara() {
        NativeExecutable exe = new NativeExecutable("yara");
        assertTrue(exe.load());
    }

    @Test
    public void testLoadYarac() {
        NativeExecutable exe = new NativeExecutable("yarac");
        assertTrue(exe.load());
    }
}
