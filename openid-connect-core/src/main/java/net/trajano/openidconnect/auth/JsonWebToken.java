package net.trajano.openidconnect.auth;

import net.trajano.openidconnect.crypto.Base64Url;
import net.trajano.openidconnect.crypto.JsonWebKeySet;

public class JsonWebToken {

    private final JoseHeader joseHeader;

    private final byte[] payload;

    private final byte[] signature;

    public JsonWebToken(JoseHeader joseHeader, byte[] payload, byte[] signature) {

        this.joseHeader = joseHeader;
        this.payload = payload;
        this.signature = signature;
    }

    @Override
    public String toString() {

        StringBuilder b = new StringBuilder(Base64Url.encode(joseHeader.toString())).append('.')
                .append(Base64Url.encode(payload));
        if (signature != null) {
            b.append('.')
                    .append(Base64Url.encode(signature));
        }
        return b.toString();

    }

    public void validateSignature(JsonWebKeySet jwks) {

    }
}
