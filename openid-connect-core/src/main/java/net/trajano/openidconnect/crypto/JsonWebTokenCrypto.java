package net.trajano.openidconnect.crypto;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Interface to hide the implementation for the JWS and JWE payload builders.
 * 
 * @author Archimedes
 */
public interface JsonWebTokenCrypto {

    /**
     * Creates the JWS payload data.
     * 
     * @param header
     *            JOSE header. This must contain the alg value
     * @param payloadBytes
     * @param jwk
     * @return
     * @throws GeneralSecurityException
     */
    byte[][] buildJWSPayload(JoseHeader header,
            byte[] payloadBytes,
            JsonWebKey jwk) throws GeneralSecurityException;

    byte[][] buildJWEPayload(JoseHeader joseHeader,
            byte[] payloadBytes,
            JsonWebKey jwk) throws IOException,
            GeneralSecurityException;

    byte[] getJWSPayload(JsonWebToken jsonWebToken,
            JsonWebKey jwk,
            JsonWebAlgorithm alg) throws IOException,
            GeneralSecurityException;;

    byte[] getJWEPayload(JsonWebToken jsonWebToken,
            JsonWebKey jwk) throws IOException,
            GeneralSecurityException;;

    byte[] inflate(byte[] compressed) throws IOException;

    byte[] deflate(byte[] uncompressed) throws IOException;

}
