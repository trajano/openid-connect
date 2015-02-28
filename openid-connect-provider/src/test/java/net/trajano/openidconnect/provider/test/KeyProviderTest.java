package net.trajano.openidconnect.provider.test;

import net.trajano.openidconnect.provider.internal.KeyProvider;

import org.junit.Test;

public class KeyProviderTest {

    @Test
    public void testKeyProvider() throws Exception {

        KeyProvider keyProvider = new KeyProvider();
        keyProvider.generateKeys();
        keyProvider.getJwk();

    }
}
