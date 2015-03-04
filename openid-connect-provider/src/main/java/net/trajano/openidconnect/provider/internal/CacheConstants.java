package net.trajano.openidconnect.provider.internal;

import javax.ws.rs.core.CacheControl;

public class CacheConstants {

    public static final CacheControl NO_CACHE;
    static {
        NO_CACHE = new CacheControl();
        NO_CACHE.setNoCache(true);
        NO_CACHE.setNoStore(true);
    }
}
