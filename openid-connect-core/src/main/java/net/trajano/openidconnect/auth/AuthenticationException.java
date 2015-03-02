package net.trajano.openidconnect.auth;

import java.net.URI;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

public class AuthenticationException extends WebApplicationException {

    /**
     * REQUIRED. Error code.
     */
    private static final String ERROR = "error";

    /**
     * OPTIONAL. Human-readable ASCII encoded text description of the error.
     */
    private static final String ERROR_DESCRIPTION = "error_description";

    /**
     * OPTIONAL. URI of a web page that includes additional information about
     * the error.
     */
    private static final String ERROR_URI = "error_uri";

    /**
     *
     */
    private static final long serialVersionUID = -8684305650194342408L;

    /**
     * OAuth 2.0 state value. REQUIRED if the Authorization Request included the
     * state parameter. Set to the value received from the Client.
     */
    private final static String STATE = "state";

    private static Response responseBuilder(final URI redirectUri,
            final AuthenticationErrorCode error,
            final String errorDescription,
            final String state,
            final URI errorUri) {

        final UriBuilder b = UriBuilder.fromUri(redirectUri)
                .queryParam(ERROR, error);
        if (errorDescription != null) {
            b.queryParam(ERROR_DESCRIPTION, errorDescription);
        }
        if (state != null) {
            b.queryParam(STATE, errorDescription);
        }
        if (errorUri != null) {
            b.queryParam(ERROR_URI, errorUri);
        }
        return Response.temporaryRedirect(b.build())
                .build();
    }

    public AuthenticationException(final AuthenticationRequest authenticationRequest, final AuthenticationErrorCode errorCode) {

        this(authenticationRequest, errorCode, null);
    }

    public AuthenticationException(final AuthenticationRequest authenticationRequest, final AuthenticationErrorCode errorCode, final String errorDescription) {

        this(authenticationRequest, errorCode, errorDescription, null);
    }

    public AuthenticationException(final AuthenticationRequest authenticationRequest, final AuthenticationErrorCode errorCode, final String errorDescription, URI errorUri) {

        super(responseBuilder(authenticationRequest.getRedirectUri(), errorCode, errorDescription, authenticationRequest.getState(), errorUri));
    }
}
