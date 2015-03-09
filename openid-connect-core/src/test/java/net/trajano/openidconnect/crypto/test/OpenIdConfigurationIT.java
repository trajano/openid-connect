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

        test("https://accounts.google.com");
    }

    @Test
    public void heroku() throws Exception {

        test("https://connect-op.herokuapp.com");
    }

    @Test
    public void microsoft() throws Exception {

        test("https://login.windows.net/common");
    }

    @Test
    public void salesforce() throws Exception {

        test("http://login.salesforce.com");
    }

    private void test(final String issuer) {

        final Client client = ClientBuilder.newBuilder()
                .register(JsonWebKeySetProvider.class)
                .build();
        final OpenIdProviderConfiguration opconfig = client.target(issuer + "/.well-known/openid-configuration")
                .request(MediaType.APPLICATION_JSON_TYPE)
                .get(OpenIdProviderConfiguration.class);
        final JsonWebKeySet jsonWebKeySet = client.target(opconfig.getJwksUri())
                .request(MediaType.APPLICATION_JSON_TYPE)
                .get(JsonWebKeySet.class);
        assertTrue(jsonWebKeySet.getKeys().length > 0);

    }

}
