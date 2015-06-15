package com.github.plusvic.yara;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * User: pba
 * Date: 6/15/15
 * Time: 4:18 PM
 */
public class TestUtils {
    public static Path getResource(String path) {
        try {
            return Paths.get(TestUtils.class.getClassLoader().getResource(path).toURI());
        }
        catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }
}
