package com.github.plusvic.yara;

import com.github.plusvic.yara.embedded.YaraImpl;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

/**
 * Yara factory
 *
 */
public class YaraFactory {
    public enum Mode {
        EMBEDDED,
        EXERNAL
    };

    public static Yara create(Mode mode) {
        switch (mode) {
            case EMBEDDED:
                return new YaraImpl();
            case EXERNAL:
                return new com.github.plusvic.yara.external.YaraImpl();
            default:
                throw new NotImplementedException();
        }
    }
}
