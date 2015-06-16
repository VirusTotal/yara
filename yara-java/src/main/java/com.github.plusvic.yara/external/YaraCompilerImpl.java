package com.github.plusvic.yara.external;

import com.github.plusvic.yara.*;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

public class YaraCompilerImpl implements YaraCompiler {
    private static final Logger LOGGER = Logger.getLogger(YaraCompilerImpl.class.getName());

    private YaraCompilationCallback callback;
    private YaracExecutable yarac;

    public YaraCompilerImpl() {
        this.yarac = new YaracExecutable();
    }

    @Override
    public void setCallback(YaraCompilationCallback cbk) {
        Preconditions.checkArgument(cbk != null);
        this.callback = cbk;
    }

    @Override
    public boolean addRules(String content, String namespace) {
        Preconditions.checkArgument(!Utils.isNullOrEmpty(content));

        try {
            String ns = (namespace != null ? namespace : YaracExecutable.GLOBAL_NAMESPACE);
            Path rule = File.createTempFile(UUID.randomUUID().toString(), "yara")
                            .toPath();

            Files.write(rule, content.getBytes(), StandardOpenOption.WRITE);
            yarac.addRule(ns, rule);

            return true;
        }
        catch (Throwable t) {
            LOGGER.log(Level.WARNING, "Failed to add rule content {0}",
                    t.getMessage());
            throw new RuntimeException(t);
        }
    }

    @Override
    public YaraScanner createScanner() {
        try {
            Path path = yarac.compile(callback);
            return new YaraScannerImpl(path);
        }
        catch (Exception e) {
            throw new YaraException(e.getMessage());
        }
    }

    @Override
    public void close() throws Exception {
    }
}
