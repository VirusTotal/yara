package com.github.plusvic.yara;

import java.util.Iterator;

abstract class GenericIterator<T> implements Iterator<T> {
    private boolean ended = false;
    private boolean used  = false;
    private T next;

    @Override
    public boolean hasNext() {
        if (ended) {
            return false;
        }
        if (!used && next != null) {
            return true;
        }

        if (null == (next = getNext())) {
            ended = true;
            return false;
        }

        return true;
    }

    @Override
    public T next() {
        if (hasNext()) {
            used = true;
        }
        return next;
    }

    protected abstract T getNext();
}
