package com.github.plusvic.yara;

import java.nio.file.Files;
import java.nio.file.Path;

public class Utils {
    /**
     * Check string is null or empty
     * @param value
     * @return
     */
    public static boolean isNullOrEmpty(String value) {
        return (value == null || value.length() <= 0) ? true : false;
    }

    /**
     * Check path exists
     * @param value
     * @return
     */
    public static boolean exists(Path value) {
        return (value == null || !Files.exists(value)) ? false : true;
    }

    /**
     * Unescape string
     * @param value
     * @return
     */
    public static String unescape(String value) {
        if (value == null || value.length() == 0) {
            return value;
        }

        StringBuffer buffer = new StringBuffer();

        int pos = 0, max = value.length();

        while (pos < max) {
            Character current = value.charAt(pos);

            if (current == '\\' && (pos + 1)  < max) {
                switch (value.charAt(pos + 1)) {
                    case '\"':
                        buffer.append('\"');
                        pos +=2;
                        break;
                    case '\'':
                        buffer.append('\'');
                        pos +=2;
                        break;
                    case '\\':
                        buffer.append('\\');
                        pos +=2;
                        break;
                    case '\n':
                        buffer.append('\n');
                        pos +=2;
                        break;
                    case '\t':
                        buffer.append('\t');
                        pos +=2;
                        break;
                    default:
                        buffer.append(current);
                        pos++;
                        break;
                }
            }
            else {
                buffer.append(current);
                pos++;
            }
        }


        return buffer.toString();
    }
}
