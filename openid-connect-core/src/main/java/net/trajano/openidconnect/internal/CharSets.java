package net.trajano.openidconnect.internal;

import java.nio.charset.Charset;

public class CharSets {

    public static final Charset US_ASCII;

    public static final Charset UTF8;

    static {
        US_ASCII = Charset.availableCharsets()
                .get("US-ASCII");
        UTF8 = Charset.availableCharsets()
                .get("UTF-8");
    }

}
