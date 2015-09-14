package com.github.plusvic.yara.external;

/**
 * Yara executable manager
 */
public class YaraExecutableManager {
    private static final Object yaraLock = new Object();
    private static volatile NativeExecutable yara;

    private static final Object yaracLock = new Object();
    private static volatile NativeExecutable yarac;

    public static NativeExecutable getYara() {
        if (yara == null) {
            synchronized (yaraLock) {
                if (yara == null) {
                    yara = new NativeExecutable("yara");
                    yara.load();
                }
            }
        }
        return yara;
    }

    public static NativeExecutable getYarac() {
        if (yarac == null) {
            synchronized (yaracLock) {
                if (yarac == null) {
                    yarac = new NativeExecutable("yarac");
                    yarac.load();
                }
            }
        }
        return yarac;
    }
}
