package com.github.plusvic.yara.external;

import com.github.plusvic.yara.Preconditions;
import com.github.plusvic.yara.Utils;
import com.github.plusvic.yara.YaraMeta;

public class YaraMetaImpl implements YaraMeta {
    private String identifier;
    private Type type;
    private String string;
    private int integer;

    public YaraMetaImpl(String identifier, String value) {
        Preconditions.checkArgument(!Utils.isNullOrEmpty(identifier));
        this.identifier = identifier;
        this.type = Type.STRING;
        this.string = value;
    }

    public YaraMetaImpl(String identifier, int value) {
        Preconditions.checkArgument(!Utils.isNullOrEmpty(identifier));
        this.identifier = identifier;
        this.type = Type.INTEGER;
        this.integer = value;
    }


    public YaraMetaImpl(String identifier, boolean value) {
        Preconditions.checkArgument(!Utils.isNullOrEmpty(identifier));
        this.identifier = identifier;
        this.type = Type.BOOLEAN;
        this.integer = value ? 1 : 0;
    }

    @Override
    public Type getType() {
        return type;
    }

    @Override
    public String getIndentifier() {
        return identifier;
    }

    @Override
    public String getString() {
        return string;
    }

    @Override
    public int getInteger() {
        return integer;
    }
}
