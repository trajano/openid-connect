package net.trajano.openidconnect.jaspic.test;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.security.Key;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.ext.MessageBodyReader;

import net.trajano.openidconnect.crypto.JsonWebKeySet;
import net.trajano.openidconnect.jaspic.internal.KeyMapBuilder;
import net.trajano.openidconnect.rs.JsonWebKeySetProvider;

import org.junit.Test;

public class JwksTest {

    @Test
    public void testGoogleJwks() throws Exception {

        final MessageBodyReader<JsonWebKeySet> reader = new JsonWebKeySetProvider();
        final JsonWebKeySet jwks = reader.readFrom(JsonWebKeySet.class, JsonWebKeySet.class, null, MediaType.APPLICATION_JSON_TYPE, null, getClass().getResourceAsStream("/googlejwks.json"));

        assertEquals(2, jwks.getKeys().length);
        Map<String, Key> keyMap = KeyMapBuilder.build(jwks);
        {
            RSAPublicKey key = (RSAPublicKey) keyMap.get("efe3dae36c5fb10efb2355b31b23ae77a86332dc");
            assertEquals(new BigInteger("65537"), key.getPublicExponent());
        }
    }
}
