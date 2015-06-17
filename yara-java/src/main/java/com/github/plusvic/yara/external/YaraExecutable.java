package com.github.plusvic.yara.external;

import com.github.plusvic.yara.Preconditions;
import com.github.plusvic.yara.Utils;
import com.github.plusvic.yara.YaraException;
import com.github.plusvic.yara.YaraScanCallback;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

public class YaraExecutable {
    private static final Logger LOGGER = Logger.getLogger(YaraExecutable.class.getName());

    private int timeout = 60;
    private NativeExecutable executable;
    private Set<Path> rules = new HashSet<>();

    public YaraExecutable() {
        this.executable = YaraExecutableManager.getYara();
    }

    public YaraExecutable(NativeExecutable executable) {
        if (executable == null) {
            throw new IllegalArgumentException();
        }
        this.executable = executable;
        this.executable.load();
    }

    public YaraExecutable addRule(Path file) {
        if (!Utils.exists(file)) {
            throw new IllegalArgumentException();
        }

        rules.add(file);
        return this;
    }

    public YaraExecutable setTimeout(int timeout) {
        Preconditions.checkArgument(timeout > 0);
        this.timeout = timeout;

        return this;
    }

    private String[] getCommandLine(Path target) {
        List<String> args = new ArrayList<>();
        //args.add("-g");  // tags
        args.add("-m"); // meta
        args.add("-s"); // strings

        for (Path path : rules) {
            args.add(path.toAbsolutePath().toString());
        }

        args.add(target.toAbsolutePath().toString());

        return args.toArray(new String[]{});
    }

    public boolean match(Path target, YaraScanCallback callback) throws Exception {
        if (target == null || callback == null) {
            throw new IllegalArgumentException();
        }

        try {
            Process process = executable.execute(getCommandLine(target));
            process.waitFor(timeout, TimeUnit.SECONDS);

            try (BufferedReader pout = new BufferedReader(new InputStreamReader(process.getInputStream()));
                 BufferedReader perr  = new BufferedReader(new InputStreamReader(process.getErrorStream())))
            {
                String line;
                while(null != (line = perr.readLine())) {
                    processError(line);
                }

                YaraOutputProcessor outputProcessor = new YaraOutputProcessor(callback);

                outputProcessor.onStart();
                while (null != (line = pout.readLine())) {
                    outputProcessor.onLine(line);
                }
                outputProcessor.onComplete();
            }

            return true;
        }
        catch (Throwable t) {
            LOGGER.log(Level.WARNING, "Failed to match rules: {0}", t.getMessage());
            throw t;
        }
    }

    private void processError(String line) {
        throw new YaraException(line);
    }
}
