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

    /**
     * 
     */
    private static final long serialVersionUID = -473305627529777783L;

    /**
     * Initializes the set with objects.
     * 
     * @param objs
     *            objects
     */
    @SafeVarargs
    public HashSet2(T... objs) {

        super(Arrays.asList(objs));
    }
}
