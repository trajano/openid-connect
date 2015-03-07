package net.trajano.openidconnect.auth;

import java.io.IOException;

import net.trajano.openidconnect.crypto.Base64Url;

/**
 * The JSON Web Token. It is comprised of a header that is a Base64url encoded
 * JSON followed by 1 to many Base64url encoded payloads joined by '.'
 * character.
 *
 * @author Archimedes
 */
public class JsonWebToken {

    private final JoseHeader joseHeader;

    private final String joseHeaderEncoded;

    private final byte[][] payloads;

    public JsonWebToken(final JoseHeader joseHeader, final byte[][] payloads) {

        this.joseHeader = joseHeader;
        this.joseHeaderEncoded = joseHeader.toString();
        this.payloads = payloads;
    }

    public JsonWebToken(String jwt) throws IOException {

        String[] tokens = jwt.split("\\.");

        joseHeaderEncoded = tokens[0];
        joseHeader = new JoseHeader(Base64Url.decodeToString(joseHeaderEncoded));
        payloads = new byte[tokens.length - 1][];
        for (int i = 1; i < tokens.length; ++i) {
            payloads[i - 1] = Base64Url.decode(tokens[i]);
        }

    }

    /**
     * Gets the encoded JOSE Header as it was provided.
     * 
     * @return
     */
    public String getJoseHeaderEncoded() {

        return joseHeaderEncoded;
    }

    public byte[] getPayload(int i) {

        return payloads[i];
    }

    public int getNumberOfPayloads() {

        return payloads.length;
    }

    @Override
    public String toString() {

        final StringBuilder b = new StringBuilder(Base64Url.encode(joseHeader.toString()));
        for (final byte[] payload : payloads) {
            b.append('.')
                    .append(Base64Url.encode(payload));
        }
        return b.toString();

    }

    public JoseHeader getJoseHeader() {

        return joseHeader;
    }

}
