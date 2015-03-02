package net.trajano.openidconnect.provider.internal;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * A {@link HashSet} that allows initialization by array and a #put method that
 * will return itself
 *
 * @author Archimedes
 * @param <T>
 */
public class HashSet2<T> extends HashSet<T> implements Set<T> {

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
    public HashSet2(final T... objs) {

        super(Arrays.asList(objs));
    }

    public HashSet2<T> put(final T obj) {

        add(obj);
        return this;
    }
}
