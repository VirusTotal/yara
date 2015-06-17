package com.github.plusvic.yara.external;


import com.github.plusvic.yara.Yara;
import com.github.plusvic.yara.YaraCompiler;

public class YaraImpl implements Yara {
    @Override
    public YaraCompiler createCompiler() {
        return new YaraCompilerImpl();
    }

    @Override
    public void close() throws Exception {
    }
}
