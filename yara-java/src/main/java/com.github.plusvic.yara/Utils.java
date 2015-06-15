package com.github.plusvic.yara;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * User: pba
 * Date: 6/15/15
 * Time: 10:03 AM
 */
public class Utils {
    public static boolean isNullOrEmpty(String value) {
        return (value == null || value.length() <= 0) ? true : false;
    }

    public static boolean exists(Path value) {
        return (value == null || !Files.exists(value)) ? false : true;
    }
}
