package net.trajano.openidconnect.provider.ejb.test;

import net.trajano.openidconnect.provider.ejb.DefaultKeyProvider;

import org.junit.Test;

public class KeyProviderTest {

    @Test
    public void testKeyProvider() throws Exception {

        DefaultKeyProvider keyProvider = new DefaultKeyProvider();
        keyProvider.generateKeys();

    }
}
