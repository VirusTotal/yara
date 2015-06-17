package com.github.plusvic.yara.external;

import com.github.plusvic.yara.*;

import java.io.File;
import java.nio.file.Path;


public class YaraScannerImpl implements YaraScanner {
    private YaraExecutable yara;
    private YaraScanCallback callback;

    public YaraScannerImpl(Path rules) {
        Preconditions.checkArgument(rules != null);
        this.yara = new YaraExecutable();
        this.yara.addRule(rules);
    }

    @Override
    public void setTimeout(int timeout) {
        this.yara.setTimeout(timeout);
    }

    @Override
    public void setCallback(YaraScanCallback cbk) {
        Preconditions.checkArgument(cbk != null);
        this.callback = cbk;
    }

    @Override
    public void scan(File file) {
        Preconditions.checkArgument(file != null);

        if (!file.exists()) {
            throw new YaraException(ErrorCode.COULD_NOT_OPEN_FILE.getValue());
        }

        try {
            yara.match(file.toPath(), callback);
        }
        catch (Exception e) {
            throw new YaraException(e.getMessage());
        }
    }

    @Override
    public void close() throws Exception {
    }
}
