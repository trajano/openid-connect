package net.trajano.openidconnect.provider.test;

import net.trajano.openidconnect.provider.internal.DefaultKeyProvider;

import org.junit.Test;

public class KeyProviderTest {

    @Test
    public void testKeyProvider() throws Exception {

        DefaultKeyProvider keyProvider = new DefaultKeyProvider();
        keyProvider.generateKeys();
        keyProvider.getJwk();

    }
}
