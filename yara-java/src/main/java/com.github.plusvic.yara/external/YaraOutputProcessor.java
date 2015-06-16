package com.github.plusvic.yara.external;

import com.github.plusvic.yara.Preconditions;
import com.github.plusvic.yara.YaraScanCallback;


class YaraOutputProcessor {
    private YaraScanCallback callback;
    private YaraRuleImpl rule;
    private YaraStringImpl   string;

    public YaraOutputProcessor(YaraScanCallback callback) {
        this.callback = callback;
    }

    public void onStart() {
    }

    /**
     * Parse output line
     * @param line
     */
    public void onLine(String line) {
        if (!line.startsWith("0x")) {
             onRule(line);
        }
        else {
            onString(line);
        }
    }

    /**
     * Complete parsing
     */
    public void onComplete() {
        if (rule != null) {
            onRuleComplete();
        }
    }

    /**
     * New rule matched
     * @param line
     */
    private void onRule(String line) {
        if (rule != null) {
            onRuleComplete();
        }

        LineTokenizer tokenizer = new LineTokenizer(line);

        /*
        // Identifier first, metadata second. Cannot be null or empty and there should
        // be only one pair of [] since we print only metadata (change this code is
        // for example we start printing tags)
        rule = new YaraRuleImpl(tokenizer.next('[').trim());
        String metadata = line.substring(tokenizer.position(), line.lastIndexOf(']'));

        // Now all gets messy because yara does not write the output properly formatted,
        // escaped quotes are printed unescaped so \" becomes " in the output
        tokenizer = new LineTokenizer(metadata);

        String name = null;
        StringBuffer value = new StringBuffer();

        do {
            if (name == null) {
                name = tokenizer.next('=');
            }
            else {
                String temp = tokenizer.next(',');

            }
        }
        while (tokenizer.position() < tokenizer.length());
        */
    }

    /**
     * Rule match completed
     */
    private void onRuleComplete() {
        callback.onMatch(rule);
        rule = null;
        string = null;
    }

    /**
     * New string match
     * @param line
     */
    private void onString(String line) {
        Preconditions.checkState(rule != null);

        // Parse string match line
        LineTokenizer tokenizer = new LineTokenizer(line);
        String offset = tokenizer.next().trim();
        String identifier = tokenizer.next().trim();
        String value = tokenizer.rest().trim();

        // Add match to string
        if (string == null || !identifier.equals(string.getIdentifier())) {
            string = new YaraStringImpl(identifier);
            rule.addString(string); // rule should not be null
        }

        string.addMatch(Integer.decode(offset), value);
    }
}
