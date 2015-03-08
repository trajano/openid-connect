package net.trajano.openidconnect.crypto;

import java.security.GeneralSecurityException;

import net.trajano.openidconnect.auth.JoseHeader;

public interface JsonWebTokenSigner {

    /**
     * Creates the signature payload data.
     * 
     * @param header
     *            JOSE header. This must contain the alg value
     * @param payloadBytes
     * @param jwk
     * @return
     * @throws GeneralSecurityException
     */
    byte[] signaturePayload(JoseHeader header,
            byte[] payloadBytes,
            JsonWebKey jwk) throws GeneralSecurityException;

}
