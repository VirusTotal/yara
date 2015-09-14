package com.github.plusvic.yara.external;


import com.github.plusvic.yara.*;

import java.util.*;

public class YaraRuleImpl implements YaraRule {
    private String indentifier;
    private List<YaraMeta> metas = new ArrayList<>();
    private List<YaraString> strings = new ArrayList<>();

    public YaraRuleImpl(String identifier) {
        Preconditions.checkArgument(!Utils.isNullOrEmpty(identifier));

        this.indentifier = identifier;
    }

    public void addMeta(YaraMeta meta) {
        this.metas.add(meta);
    }

    public void addString(YaraString string) {
        this.strings.add(string);
    }

    @Override
    public String getIdentifier() {
        return indentifier;
    }

    @Override
    public Iterator<YaraMeta> getMetadata() {
        return metas.iterator();
    }

    @Override
    public Iterator<YaraString> getStrings() {
        return strings.iterator();
    }
}
