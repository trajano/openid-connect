package net.trajano.openidconnect.provider.internal;

import java.net.URI;

import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.auth.AuthenticationResponse;

/**
 * Performs conversions of {@link AuthenticationResponse} to other forms.
 * 
 * @author Archimedes
 */
public class AuthenticationResponseConverter {

    private static final String ACCESS_TOKEN_KEY = "access_token";

    private static final String CODE_KEY = "code";

    private static final String ID_TOKEN_KEY = "id_token";

    private static final String STATE_KEY = "state";

    private static final String TOKEN_TYPE_KEY = "token_type";

    public AuthenticationResponseConverter(URI redirectUri, AuthenticationResponse response) {

        this.redirectUri = redirectUri;
        this.response = response;
    }

    private final URI redirectUri;

    private final AuthenticationResponse response;

    public String toFormPost() {

        final FormPostBuilder b = new FormPostBuilder(redirectUri);
        if (response.getState() != null) {
            b.put(STATE_KEY, response.getState());
        }
        if (response.getAccessToken() != null) {
            b.put(ACCESS_TOKEN_KEY, response.getAccessToken());
            b.put(TOKEN_TYPE_KEY, response.getTokenType());
        }
        if (response.getCode() != null) {
            b.put(CODE_KEY, response.getCode());
        }
        if (response.getEncodedIdToken() != null) {
            b.put(ID_TOKEN_KEY, response.getEncodedIdToken());
        }
        return b.buildFormPost();
    }

    public URI toFragmentUri() {

        return UriBuilder.fromUri(redirectUri)
                .fragment(toQueryUri().getQuery())
                .build();
    }

    public URI toQueryUri() {

        final UriBuilder b = UriBuilder.fromUri(redirectUri);
        if (response.getState() != null) {
            b.queryParam(STATE_KEY, response.getState());
        }
        if (response.getAccessToken() != null) {
            b.queryParam(ACCESS_TOKEN_KEY, response.getAccessToken());
            b.queryParam(TOKEN_TYPE_KEY, response.getTokenType());
        }
        if (response.getCode() != null) {
            b.queryParam(CODE_KEY, response.getCode());
        }
        if (response.getEncodedIdToken() != null) {
            b.queryParam(ID_TOKEN_KEY, response.getEncodedIdToken());
        }
        return b.build();
    }
}
