package net.trajano.openidconnect.crypto.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import javax.json.Json;
import javax.json.JsonArray;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.MessageBodyWriter;

import net.trajano.openidconnect.crypto.JsonWebAlgorithm;
import net.trajano.openidconnect.crypto.JsonWebKey;
import net.trajano.openidconnect.crypto.JsonWebKeySet;
import net.trajano.openidconnect.rs.JsonWebKeySetProvider;

import org.junit.Test;

public class JwksTest {

    @Test
    public void testAlgo() throws Exception {

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

        final RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        System.out.println(publicKey.getAlgorithm());
        System.out.println(privateKey.getAlgorithm());
        System.out.println(JsonWebAlgorithm.fromJca(publicKey.getAlgorithm()));

    }

    @Test
    public void testGoogleJwks() throws Exception {

        final MessageBodyReader<JsonWebKeySet> reader = new JsonWebKeySetProvider();
        final JsonWebKeySet jwks = reader.readFrom(JsonWebKeySet.class, JsonWebKeySet.class, null, MediaType.APPLICATION_JSON_TYPE, null, getClass().getResourceAsStream("/googlejwks.json"));

        final JsonWebKey[] keys = jwks.getKeys();
        assertEquals(2, keys.length);
        assertEquals(JsonWebAlgorithm.RS256, keys[0].getAlg());
        assertEquals(JsonWebAlgorithm.RS256, keys[1].getAlg());

        final RSAPublicKey jcaKey = (RSAPublicKey) keys[1].toJcaKey();
        assertNotEquals(jcaKey.getModulus(), BigInteger.ZERO);
        assertNotEquals(jcaKey.getPublicExponent(), BigInteger.ZERO);
    }

    @Test
    public void testGoogleJwksRewrite() throws Exception {

        final MessageBodyReader<JsonWebKeySet> reader = new JsonWebKeySetProvider();
        final JsonWebKeySet jwks = reader.readFrom(JsonWebKeySet.class, JsonWebKeySet.class, null, MediaType.APPLICATION_JSON_TYPE, null, getClass().getResourceAsStream("/googlejwks.json"));

        final JsonWebKey[] keys = jwks.getKeys();
        assertEquals(2, keys.length);
        assertEquals(JsonWebAlgorithm.RS256, keys[0].getAlg());
        assertEquals(JsonWebAlgorithm.RS256, keys[1].getAlg());

        final RSAPublicKey jcaKey = (RSAPublicKey) keys[1].toJcaKey();
        assertNotEquals(jcaKey.getModulus(), BigInteger.ZERO);
        assertNotEquals(jcaKey.getPublicExponent(), BigInteger.ZERO);

        final MessageBodyWriter<JsonWebKeySet> writer = new JsonWebKeySetProvider();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        writer.writeTo(jwks, JsonWebKeySet.class, null, null, MediaType.APPLICATION_JSON_TYPE, null, baos);
        baos.close();

        JsonArray googleKeys = Json.createReader(getClass().getResourceAsStream("/googlejwks.json"))
                .readObject()
                .getJsonArray("keys");

        JsonArray builtKeys = Json.createReader(new ByteArrayInputStream(baos.toByteArray()))
                .readObject()
                .getJsonArray("keys");

        if (googleKeys.getJsonObject(0)
                .getString("kid")
                .equals(builtKeys.getJsonObject(0)
                        .getString("kid"))) {
            assertEquals(googleKeys.getJsonObject(0), builtKeys.getJsonObject(0));
            assertEquals(googleKeys.getJsonObject(1), builtKeys.getJsonObject(1));
        } else {
            assertEquals(googleKeys.getJsonObject(0), builtKeys.getJsonObject(1));
            assertEquals(googleKeys.getJsonObject(1), builtKeys.getJsonObject(0));
        }

    }
}
