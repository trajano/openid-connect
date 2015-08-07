package net.trajano.openidconnect.jaspic.test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.json.Json;
import javax.json.JsonObject;

import org.junit.Test;

import net.trajano.openidconnect.crypto.Encoding;
import net.trajano.openidconnect.internal.CharSets;
import net.trajano.openidconnect.jaspic.internal.Utils;

public class ValidateAtHashTest {

    public String hash(final String token) throws NoSuchAlgorithmException {

        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        final byte[] digestedBytes = digest.digest(token.getBytes(CharSets.US_ASCII));

        return Encoding.base64urlEncode(digestedBytes, 0, 128 / 8);
    }

    @Test
    public void testIdTokenValidator() throws Exception {

        final JsonObject idTokenJson = Json.createObjectBuilder().add("aud", "clientId").add("nonce", "nonce").build();
        Utils.validateIdToken("clientId", idTokenJson, "nonce", "ACCESS");
    }
}
