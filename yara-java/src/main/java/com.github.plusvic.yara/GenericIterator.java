package com.github.plusvic.yara;

import java.util.Iterator;
import java.util.NoSuchElementException;

abstract class GenericIterator<T> implements Iterator<T> {
    private boolean ended = false;
    private T next;

    @Override
    public boolean hasNext() {
        if (ended) {
            return false;
        }

        if (next == null) {
            if (null == (next = getNext())) {
                ended = true;
            }
        }

        return (next != null);
    }

    @Override
    public T next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }

        T temp = next;
        next = null;
        return temp;
    }

    protected abstract T getNext();
}
