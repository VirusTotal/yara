package com.github.plusvic.yara.external;

import org.fusesource.hawtjni.runtime.Library;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.text.MessageFormat;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Native executable dependency
 *
 */
public class NativeExecutable {
    private static final Logger LOGGER = Logger.getLogger(NativeExecutable.class.getName());
    private static final Set<PosixFilePermission> EXECUTABLE_PERMISSIONS = new HashSet<>();

    static  {
        EXECUTABLE_PERMISSIONS.add(PosixFilePermission.GROUP_EXECUTE);
        EXECUTABLE_PERMISSIONS.add(PosixFilePermission.GROUP_READ);
        EXECUTABLE_PERMISSIONS.add(PosixFilePermission.GROUP_WRITE);
        EXECUTABLE_PERMISSIONS.add(PosixFilePermission.OWNER_EXECUTE);
        EXECUTABLE_PERMISSIONS.add(PosixFilePermission.OWNER_READ);
        EXECUTABLE_PERMISSIONS.add(PosixFilePermission.OWNER_WRITE);
        EXECUTABLE_PERMISSIONS.add(PosixFilePermission.OTHERS_EXECUTE);
        EXECUTABLE_PERMISSIONS.add(PosixFilePermission.OTHERS_READ);
        EXECUTABLE_PERMISSIONS.add(PosixFilePermission.OTHERS_WRITE);
    }

    private final String name;
    private final ClassLoader classLoader;
    private Path localPath;

    public NativeExecutable(String name) {
        this(name, (ClassLoader) null);
    }

    public NativeExecutable(String name, Class<?> clazz) {
        this(name, clazz.getClassLoader());
    }

    public NativeExecutable(String name, ClassLoader classLoader) {
        if(name == null || name.length() == 0) {
            throw new IllegalArgumentException();
        } else {
            this.name = name;
            this.classLoader = classLoader != null ?
                                    classLoader :
                                    NativeExecutable.class.getClassLoader();
        }
    }

    public synchronized boolean load() {
        if(localPath == null) {
            localPath = doLoad();
        }
        return localPath != null;
    }

    private static String version(Class<?> clazz) {
        try {
            return clazz.getPackage().getImplementationVersion();
        } catch (Throwable var2) {
            return null;
        }
    }

    private static String getEmbeddedPath(String name) {
        String platform = Library.getOperatingSystem();

        if ("osx".equals(platform)) {
            return String.format("META-INF/native/%s/%s", platform, name);
        }

        return  String.format("META-INF/native/%s/%s", Library.getPlatform(), name);
    }

    private Path doLoad() {
        String resourcePath = getEmbeddedPath(name);

        try {
            Path tempPath = File.createTempFile(name, Integer.toString(UUID.randomUUID().hashCode())).toPath();

            URL resource = this.classLoader.getResource(resourcePath);
            if (resource != null) {
                try (InputStream is = resource.openStream()) {
                    Files.copy(is, tempPath, StandardCopyOption.REPLACE_EXISTING);
                }
                Files.setPosixFilePermissions(tempPath, EXECUTABLE_PERMISSIONS);

                return tempPath;
            }
        }
        catch (IOException ioe) {
            LOGGER.log(Level.WARNING, MessageFormat.format("Failed to write executable to {0}: {1}",
                    localPath, ioe.toString()));
        }

        return null;
    }

    /**
     * Run executable
     * @param args
     * @return
     * @throws Exception
     */
    public Process execute(String...args) throws Exception {
        if (localPath == null) {
            throw new IllegalStateException();
        }

        List<String> command = new ArrayList<>();
        command.add(localPath.toString());

        if (args != null) {
            for (String arg: args) {
                command.add(arg);
            }
        }

        return new ProcessBuilder(command).start();
    }
}
