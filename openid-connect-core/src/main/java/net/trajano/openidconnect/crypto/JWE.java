package net.trajano.openidconnect.crypto;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.zip.DataFormatException;

import javax.json.JsonObject;

import net.trajano.openidconnect.internal.CharSets;

public class JWE {

    public static byte[] decrypt(final JsonWebToken jsonWebToken,
            final JsonWebKey jwk) throws IOException,
            GeneralSecurityException {

        JsonWebTokenProcessor p = new JsonWebTokenProcessor(jsonWebToken);
        p.jwk(jwk);
        return p.getPayload();
    }

    public static byte[] decrypt(final String jwe,
            final JsonWebKey jwk) throws IOException,
            GeneralSecurityException,
            DataFormatException {

        final JsonWebToken jsonWebToken = new JsonWebToken(jwe);
        return decrypt(jsonWebToken, jwk);
    }

    public static String encrypt(final byte[] plaintext,
            final JsonWebKey jwk,
            final String alg,
            final String enc) throws IOException,
            GeneralSecurityException {

        return encrypt(plaintext, jwk, alg, enc, false);
    }

    public static String encrypt(final byte[] plaintext,
            final JsonWebKey jwk,
            final String alg,
            final String enc,
            final boolean compress) throws IOException,
            GeneralSecurityException {

        JsonWebTokenBuilder b = new JsonWebTokenBuilder();
        b.payload(plaintext);
        b.jwk(jwk);
        b.alg(alg);
        b.enc(enc);
        b.compress(compress);
        return b.toString();
    }

    public static String encrypt(final JsonObject obj,
            final JsonWebKey jwk,
            final String alg,
            final String enc) throws IOException,
            GeneralSecurityException {

        return encrypt(obj.toString()
                .getBytes(CharSets.UTF8), jwk, alg, enc, false);
    }
}
