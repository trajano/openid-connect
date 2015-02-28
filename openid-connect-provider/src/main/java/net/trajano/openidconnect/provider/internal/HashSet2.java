package net.trajano.openidconnect.provider.internal;

import java.util.Arrays;
import java.util.HashSet;

/**
 * A {@link HashSet} that allows initialization by array.
 * 
 * @author Archimedes
 * @param <T>
 */
public class HashSet2<T> extends HashSet<T> {

    public HashSet2(T... objs) {

        super(Arrays.asList(objs));
    }
}
