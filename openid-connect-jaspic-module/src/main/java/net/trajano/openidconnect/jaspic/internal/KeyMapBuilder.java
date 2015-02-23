package net.trajano.openidconnect.jaspic.internal;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.json.JsonObject;
import javax.json.JsonValue;

import net.trajano.openidconnect.crypto.Base64Url;
import net.trajano.openidconnect.crypto.JsonWebKey;
import net.trajano.openidconnect.crypto.JsonWebKeySet;

/**
 * This builds a map of key id to keys based on a {@link JsonObject}. Implements
 * http://tools.ietf.org/html/draft-ietf-jose-json-web-key-29.
 *
 * @TODO This would be in the JASPIC module
 * @author Archimedes
 */
public class KeyMapBuilder {

    public static Map<String, Key> build(final JsonWebKeySet jwks) throws GeneralSecurityException {

        final Map<String, Key> keyMap = new HashMap<>();
        for (final JsonWebKey key : jwks.getKeys()) {
            keyMap.put(key.getKid(), key.toJcaKey());
        }
        return keyMap;
    }

    public static Map<String, Key> build(final JsonObject jwks) throws GeneralSecurityException {

        final Map<String, Key> keyMap = new HashMap<>();
        for (final JsonValue key : jwks.getJsonArray("keys")) {
            final JsonObject keyObject = (JsonObject) key;
            final String kid = keyObject.getString("kid");
            final String kty = keyObject.getString("kty");
            if ("RSA".equals(kty)) {
                keyMap.put(kid, buildRsaKey(keyObject));
            } else if ("EC".equals(kty)) {
                keyMap.put(kid, buildEcKey(keyObject));
            } else if ("oct".equals(kty)) {
                keyMap.put(kid, buildOctKey(keyObject));
            } else {
                throw new NoSuchAlgorithmException("kty of " + kty + " is not supported");
            }
        }
        return keyMap;
    }

    private static Key buildEcKey(final JsonObject keyObject) {

        // TODO Auto-generated method stub
        return null;
    }

    private static Key buildOctKey(final JsonObject keyObject) {

        // TODO Auto-generated method stub
        return null;
    }

    private static Key buildRsaKey(final JsonObject keyObject) throws GeneralSecurityException {

        if ("sig".equals(keyObject.getString("use"))) {
            return buildRsaPublicKey(keyObject);
        }
        return null;
    }

    private static Key buildRsaPublicKey(final JsonObject keyObject) throws GeneralSecurityException {

        final BigInteger modulus = Base64Url.decodeUint(keyObject.getString("n"));
        final BigInteger publicExponent = Base64Url.decodeUint(keyObject.getString("e"));
        return KeyFactory.getInstance("RSA")
                .generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
    }
}
