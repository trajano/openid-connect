package net.trajano.openidconnect.core;

import java.net.URI;

import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

public class InvalidClientException extends NotAuthorizedException {

    /**
     * 
     */
    private static final long serialVersionUID = 6647799059101432680L;

    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";

    public InvalidClientException() {

        super(Response.noContent()
                .header(WWW_AUTHENTICATE, buildWwwAuthenticateHeader(null, null))
                .status(Status.UNAUTHORIZED)
                .build());
    }

    public InvalidClientException(String errorDescription) {

        super(Response.noContent()
                .header(WWW_AUTHENTICATE, buildWwwAuthenticateHeader(errorDescription, null))
                .status(Status.UNAUTHORIZED)
                .build());

    }

    public InvalidClientException(String errorDescription, URI errorUri) {

        super(Response.noContent()
                .header(WWW_AUTHENTICATE, buildWwwAuthenticateHeader(errorDescription, errorUri))
                .status(Status.UNAUTHORIZED)
                .build());

    }

    private static String buildWwwAuthenticateHeader(String errorDescription,
            URI errorUri) {

        StringBuilder b = new StringBuilder("error=\"invalid_client\"");
        if (errorDescription != null) {
            b.append("error_description=\"");
            b.append(errorDescription);
            b.append("\"");
        }
        if (errorUri != null) {
            b.append("error_uri=\"");
            b.append(errorUri);
            b.append("\"");
        }
        return b.toString();
    }
}
