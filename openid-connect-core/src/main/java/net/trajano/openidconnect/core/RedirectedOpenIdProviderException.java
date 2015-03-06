package net.trajano.openidconnect.core;

import static net.trajano.openidconnect.core.OpenIdConnectKey.ERROR;
import static net.trajano.openidconnect.core.OpenIdConnectKey.ERROR_DESCRIPTION;
import static net.trajano.openidconnect.core.OpenIdConnectKey.ERROR_URI;
import static net.trajano.openidconnect.core.OpenIdConnectKey.STATE;

import java.net.URI;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.auth.AuthenticationRequest;

/**
 * Renders the {@link OpenIdConnectException} as a redirect with an optional
 * state value. It will only render {@value } OpenIdConnectKey#ERROR},
 * {@value OpenIdConnectKey#ERROR_DESCRIPTION} and {@value }
 * {@value OpenIdConnectKey#ERROR_URI} from the response.
 * 
 * @author Archimedes Trajano
 */
public class RedirectedOpenIdProviderException extends WebApplicationException {

    /**
     *
     */
    private static final long serialVersionUID = -8684305650194342408L;

    private static Response responseBuilder(final URI redirectUri,
            final ErrorResponse errorResponse,
            final String state) {

        final UriBuilder b = UriBuilder.fromUri(redirectUri)
                .queryParam(ERROR, errorResponse.getError());
        if (errorResponse.getErrorDescription() != null) {
            b.queryParam(ERROR_DESCRIPTION, errorResponse.getErrorDescription());
        }
        if (errorResponse.getErrorUri() != null) {
            b.queryParam(ERROR_URI, errorResponse.getErrorUri());
        }
        if (state != null) {
            b.queryParam(STATE, state);
        }
        return Response.temporaryRedirect(b.build())
                .build();
    }

    /**
     * Convenience constructor as this exception type is generally part of
     * authentication.
     * 
     * @param authenticationRequest
     * @param errorResponse
     */
    public RedirectedOpenIdProviderException(final AuthenticationRequest authenticationRequest, ErrorResponse errorResponse) {

        this(authenticationRequest.getRedirectUri(), errorResponse, authenticationRequest.getState());
    }

    public RedirectedOpenIdProviderException(URI redirectUri, ErrorResponse errorResponse) {

        this(redirectUri, errorResponse, null);
    }

    public RedirectedOpenIdProviderException(URI redirectUri, ErrorResponse errorResponse, String state) {

        super(responseBuilder(redirectUri, errorResponse, state));
    }
}
