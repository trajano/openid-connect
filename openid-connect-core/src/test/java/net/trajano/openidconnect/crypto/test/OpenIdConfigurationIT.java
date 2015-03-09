package net.trajano.openidconnect.crypto.test;

import static org.junit.Assert.assertTrue;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.MediaType;

import net.trajano.openidconnect.core.OpenIdProviderConfiguration;
import net.trajano.openidconnect.crypto.JsonWebKeySet;
import net.trajano.openidconnect.rs.JsonWebKeySetProvider;

import org.junit.Test;

public class OpenIdConfigurationIT {

    @Test
    public void google() throws Exception {

        Client client = ClientBuilder.newBuilder()
                .register(JsonWebKeySetProvider.class)
                .build();
        OpenIdProviderConfiguration opconfig = client.target("https://accounts.google.com/.well-known/openid-configuration")
                .request(MediaType.APPLICATION_JSON_TYPE)
                .get(OpenIdProviderConfiguration.class);
        JsonWebKeySet jsonWebKeySet = client.target(opconfig.getJwksUri())
                .request(MediaType.APPLICATION_JSON_TYPE)
                .get(JsonWebKeySet.class);
        assertTrue(jsonWebKeySet.getKeys().length > 0);

    }
}
