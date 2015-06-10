package com.github.plusvic.yara;

import net.jcip.annotations.NotThreadSafe;
import org.junit.Test;

/**
 * User: pba
 * Date: 6/5/15
 * Time: 3:01 PM
 */
@NotThreadSafe
public class YaraLibraryTest {
    @Test
    public void testCreate() {
        new YaraLibrary();
    }

    @Test
    public void testInitialize() {
        YaraLibrary library = new YaraLibrary();
        library.yr_initialize();
    }

    @Test
    public void testFinalize() {
        YaraLibrary library = new YaraLibrary();
        library.yr_initialize();
        library.yr_finalize();
    }
}
