package com.github.plusvic.yara.external;


import com.github.plusvic.yara.*;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class YaraRuleImpl implements YaraRule {
    private String indentifier;
    private Set<YaraMeta> metas = new HashSet<>();
    private Set<YaraString> strings = new HashSet<>();

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
        return getIdentifier();
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
