package net.trajano.openidconnect.provider.ejb.test;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Providers;

import net.trajano.openidconnect.crypto.JsonWebKeySet;
import net.trajano.openidconnect.provider.ejb.DefaultKeyProvider;
import net.trajano.openidconnect.rs.JsonWebKeyProvider;
import net.trajano.openidconnect.rs.JsonWebKeySetProvider;

import org.junit.BeforeClass;
import org.junit.Test;

public class KeyProviderTest {

    private static Providers providers;

    @BeforeClass
    public static void setupProviders() {

        final JaxRsProviders providers = new JaxRsProviders();
        providers.add(new JsonWebKeyProvider());
        final JsonWebKeySetProvider jsonWebKeySetProvider = new JsonWebKeySetProvider();
        jsonWebKeySetProvider.setProviders(providers);
        providers.add(jsonWebKeySetProvider);
        KeyProviderTest.providers = providers;
    }

    @Test
    public void testKeyProvider() throws Exception {

        final DefaultKeyProvider keyProvider = new DefaultKeyProvider();
        keyProvider.generateKeys();

    }

    @Test
    public void testPrivateJwksToJson() throws Exception {

        final DefaultKeyProvider keyProvider = new DefaultKeyProvider();
        keyProvider.generateKeys();

        final MessageBodyWriter<JsonWebKeySet> writer = providers.getMessageBodyWriter(JsonWebKeySet.class, null, null, MediaType.APPLICATION_JSON_TYPE);
        writer.writeTo(keyProvider.getPrivateJwks(), JsonWebKeySet.class, null, null, MediaType.APPLICATION_JSON_TYPE, null, System.out);

    }

    @Test
    public void testPublicJwksToJson() throws Exception {

        final DefaultKeyProvider keyProvider = new DefaultKeyProvider();
        keyProvider.generateKeys();

        final MessageBodyWriter<JsonWebKeySet> writer = providers.getMessageBodyWriter(JsonWebKeySet.class, null, null, MediaType.APPLICATION_JSON_TYPE);
        writer.writeTo(keyProvider.getJwks(), JsonWebKeySet.class, null, null, MediaType.APPLICATION_JSON_TYPE, null, System.out);

    }

    @Test
    public void testPublicPrivateJwksToJsonEquivalency() throws Exception {

        final DefaultKeyProvider keyProvider = new DefaultKeyProvider();
        keyProvider.generateKeys();

        final MessageBodyWriter<JsonWebKeySet> writer = providers.getMessageBodyWriter(JsonWebKeySet.class, null, null, MediaType.APPLICATION_JSON_TYPE);

        final JsonArray privateJwks;
        {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            writer.writeTo(keyProvider.getPrivateJwks(), JsonWebKeySet.class, null, null, MediaType.APPLICATION_JSON_TYPE, null, baos);
            baos.close();
            final JsonReader jsonReader = Json.createReader(new ByteArrayInputStream(baos.toByteArray()));
            privateJwks = jsonReader.readObject()
                    .getJsonArray("keys");
        }
        final JsonArray publicJwks;
        {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            writer.writeTo(keyProvider.getJwks(), JsonWebKeySet.class, null, null, MediaType.APPLICATION_JSON_TYPE, null, baos);
            baos.close();
            final JsonReader jsonReader = Json.createReader(new ByteArrayInputStream(baos.toByteArray()));
            publicJwks = jsonReader.readObject()
                    .getJsonArray("keys");
        }

        int found = 0;
        for (int i = 0; i < publicJwks.size(); ++i) {
            for (int j = 0; j < privateJwks.size(); ++j) {
                final JsonObject publicJwk = publicJwks.getJsonObject(i);
                final JsonObject privateJwk = privateJwks.getJsonObject(j);
                if (publicJwk.getString("kid")
                        .equals(privateJwk.getString("kid"))) {
                    assertEquals(publicJwk.getString("kid"), privateJwk.getString("kid"));
                    assertEquals(publicJwk.getString("alg"), privateJwk.getString("alg"));
                    assertEquals("sig", publicJwk.getString("use"));
                    assertEquals("enc", privateJwk.getString("use"));
                    assertEquals(publicJwk.getString("n"), privateJwk.getString("n"));
                    found++;
                }
            }
        }
        assertEquals(publicJwks.size(), found);

    }
}
