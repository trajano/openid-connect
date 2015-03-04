package net.trajano.openidconnect.auth;

import java.net.URI;

import javax.ws.rs.core.UriBuilder;
import javax.xml.bind.annotation.XmlElement;

import net.trajano.openidconnect.internal.FormPostBuilder;

public class AuthenticationResponse {

    private static final String ACCESS_TOKEN_KEY = "access_token";

    private static final String CODE_KEY = "code";

    private static final String ID_TOKEN_KEY = "id_token";

    private static final String STATE_KEY = "state";

    private static final String TOKEN_TYPE_KEY = "token_type";

    @XmlElement(name = ACCESS_TOKEN_KEY)
    private String accessToken;

    private String code;

    @XmlElement(name = ID_TOKEN_KEY)
    private String encodedIdToken;

    private String state;

    @XmlElement(name = TOKEN_TYPE_KEY)
    private String tokenType;

    public String getAccessToken() {

        return accessToken;
    }

    public String getCode() {

        return code;
    }

    public String getEncodedIdToken() {

        return encodedIdToken;
    }

    public String getState() {

        return state;
    }

    public String getTokenType() {

        return tokenType;
    }

    public void setAccessToken(final String tokenType,
            final String accessToken) {

        this.tokenType = tokenType;
        this.accessToken = accessToken;

    }

    public void setCode(final String code) {

        this.code = code;
    }

    public void setEncodedIdToken(final String encodedIdToken) {

        this.encodedIdToken = encodedIdToken;
    }

    public void setState(final String state) {

        this.state = state;
    }

    public String toFormPost(final URI redirectUri) {

        final FormPostBuilder b = new FormPostBuilder(redirectUri);
        if (state != null) {
            b.put(STATE_KEY, state);
        }
        if (accessToken != null) {
            b.put(ACCESS_TOKEN_KEY, accessToken);
            b.put(TOKEN_TYPE_KEY, tokenType);
        }
        if (code != null) {
            b.put(CODE_KEY, code);
        }
        if (encodedIdToken != null) {
            b.put(ID_TOKEN_KEY, encodedIdToken);
        }
        return b.buildFormPost();
    }

    public URI toFragmentUri(final URI redirectUri) {

        return UriBuilder.fromUri(redirectUri)
                .fragment(toQueryUri(redirectUri).getQuery())
                .build();
    }

    public URI toQueryUri(final URI redirectUri) {

        final UriBuilder b = UriBuilder.fromUri(redirectUri);
        if (state != null) {
            b.queryParam(STATE_KEY, state);
        }
        if (accessToken != null) {
            b.queryParam(ACCESS_TOKEN_KEY, accessToken);
            b.queryParam(TOKEN_TYPE_KEY, tokenType);
        }
        if (code != null) {
            b.queryParam(CODE_KEY, code);
        }
        if (encodedIdToken != null) {
            b.queryParam(ID_TOKEN_KEY, encodedIdToken);
        }
        return b.build();
    }

}
