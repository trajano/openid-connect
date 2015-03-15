package net.trajano.openidconnect.crypto.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObjectBuilder;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Providers;

import net.trajano.openidconnect.crypto.JsonWebAlgorithm;
import net.trajano.openidconnect.crypto.JsonWebKey;
import net.trajano.openidconnect.crypto.JsonWebKeySet;
import net.trajano.openidconnect.crypto.NamedEllipticCurve;
import net.trajano.openidconnect.crypto.OctWebKey;
import net.trajano.openidconnect.jaxrs.test.JaxRsProviders;
import net.trajano.openidconnect.rs.JsonWebKeyProvider;
import net.trajano.openidconnect.rs.JsonWebKeySetProvider;

import org.junit.BeforeClass;
import org.junit.Test;

public class JwksTest {

    private static Providers providers;

    @BeforeClass
    public static void setupProviders() {

        final JaxRsProviders providers = new JaxRsProviders();
        providers.add(new JsonWebKeyProvider());
        final JsonWebKeySetProvider jsonWebKeySetProvider = new JsonWebKeySetProvider();
        jsonWebKeySetProvider.setProviders(providers);
        providers.add(jsonWebKeySetProvider);
        JwksTest.providers = providers;
    }

    @Test
    public void testAlgo() throws Exception {

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

        final RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        assertNotNull(privateKey);
        assertNotNull(publicKey);

    }

    @Test
    public void testECValues() {

        System.out.println(new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16).toString(10));
        System.out.println(new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16).toString(10));

        System.out.println(NamedEllipticCurve.P192);
    }

    @Test
    public void testGoogleJwks() throws Exception {

        final MessageBodyReader<JsonWebKeySet> reader = providers.getMessageBodyReader(JsonWebKeySet.class, null, null, MediaType.APPLICATION_JSON_TYPE);
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

        final MessageBodyReader<JsonWebKeySet> reader = providers.getMessageBodyReader(JsonWebKeySet.class, null, null, MediaType.APPLICATION_JSON_TYPE);
        assertNotNull("unable to get reader", reader);

        final JsonWebKeySet jwks = reader.readFrom(JsonWebKeySet.class, JsonWebKeySet.class, null, MediaType.APPLICATION_JSON_TYPE, null, getClass().getResourceAsStream("/googlejwks.json"));

        final JsonWebKey[] keys = jwks.getKeys();
        assertEquals(2, keys.length);
        assertEquals(JsonWebAlgorithm.RS256, keys[0].getAlg());
        assertEquals(JsonWebAlgorithm.RS256, keys[1].getAlg());

        final RSAPublicKey jcaKey = (RSAPublicKey) keys[1].toJcaKey();
        assertNotEquals(jcaKey.getModulus(), BigInteger.ZERO);
        assertNotEquals(jcaKey.getPublicExponent(), BigInteger.ZERO);

        final MessageBodyWriter<JsonWebKeySet> writer = providers.getMessageBodyWriter(JsonWebKeySet.class, null, null, MediaType.APPLICATION_JSON_TYPE);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        writer.writeTo(jwks, JsonWebKeySet.class, null, null, MediaType.APPLICATION_JSON_TYPE, null, baos);
        baos.close();

        final JsonArray googleKeys = Json.createReader(getClass().getResourceAsStream("/googlejwks.json"))
                .readObject()
                .getJsonArray("keys");

        final JsonArray builtKeys = Json.createReader(new ByteArrayInputStream(baos.toByteArray()))
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

    @Test
    public void testOct() throws Exception {

        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        final SecretKey secretKey = keyGenerator.generateKey();

        final OctWebKey octWebKey = new OctWebKey(secretKey, JsonWebAlgorithm.A128CBC);
        octWebKey.setKid("f");

        final JsonObjectBuilder b = Json.createObjectBuilder();
        octWebKey.buildJsonObject(b);

        assertArrayEquals(secretKey.getEncoded(), octWebKey.toJcaKey()
                .getEncoded());

    }
}
