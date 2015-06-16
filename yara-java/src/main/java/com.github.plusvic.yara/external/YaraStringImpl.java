package com.github.plusvic.yara.external;

import com.github.plusvic.yara.Preconditions;
import com.github.plusvic.yara.Utils;
import com.github.plusvic.yara.YaraMatch;
import com.github.plusvic.yara.YaraString;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class YaraStringImpl implements YaraString {
    private String identifier;
    private Set<YaraMatch> matches = new HashSet<>();

    public YaraStringImpl(String identifier) {
        Preconditions.checkArgument(!Utils.isNullOrEmpty(identifier));
        this.identifier = identifier;
    }

    public void addMatch(long offset, String value) {
        this.matches.add(new YaraMatchImpl(offset, value));
    }

    @Override
    public String getIdentifier() {
        return identifier;
    }

    @Override
    public Iterator<YaraMatch> getMatches() {
        return matches.iterator();
    }
}
