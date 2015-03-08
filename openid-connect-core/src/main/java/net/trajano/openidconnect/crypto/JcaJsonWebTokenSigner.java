package net.trajano.openidconnect.crypto;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;

import net.trajano.openidconnect.auth.JoseHeader;
import net.trajano.openidconnect.internal.CharSets;

public class JcaJsonWebTokenSigner implements JsonWebTokenSigner {

    @Override
    public byte[] signaturePayload(JoseHeader header,
            byte[] payloadBytes,
            JsonWebKey jwk) throws GeneralSecurityException {

        final StringBuilder b = new StringBuilder(Base64Url.encode(header.toString())).append('.')
                .append(Base64Url.encode(payloadBytes));

        final Signature signature = Signature.getInstance(header.getAlg().toJca());
        signature.initSign((PrivateKey) jwk.toJcaKey());
        signature.update(b.toString()
                .getBytes(CharSets.US_ASCII));
        return signature.sign();
    }
}
