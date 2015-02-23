package net.trajano.openidconnect.crypto;

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

/**
 * This builds a map of key id to keys based on a {@link JsonObject}. Implements
 * http://tools.ietf.org/html/draft-ietf-jose-json-web-key-29.
 * 
 * @TODO This would be in the JASPIC module
 * @author Archimedes
 */
public class KeyMapBuilder {

    public static Map<String, Key> build(JsonObject jwks) throws GeneralSecurityException {

        Map<String, Key> keyMap = new HashMap<>();
        for (JsonValue key : jwks.getJsonArray("keys")) {
            JsonObject keyObject = (JsonObject) key;
            String kid = keyObject.getString("kid");
            String kty = keyObject.getString("kty");
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

    private static Key buildOctKey(JsonObject keyObject) {

        // TODO Auto-generated method stub
        return null;
    }

    private static Key buildEcKey(JsonObject keyObject) {

        // TODO Auto-generated method stub
        return null;
    }

    private static Key buildRsaKey(JsonObject keyObject) throws GeneralSecurityException {

        if ("sig".equals(keyObject.getString("use"))) {
            return buildRsaPublicKey(keyObject);
        }
        return null;
    }

    private static Key buildRsaPublicKey(JsonObject keyObject) throws GeneralSecurityException {

        final BigInteger modulus = Base64Url.decodeUint(keyObject.getString("n"));
        final BigInteger publicExponent = Base64Url.decodeUint(keyObject.getString("e"));
        return KeyFactory.getInstance("RSA")
                .generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
    }
}
