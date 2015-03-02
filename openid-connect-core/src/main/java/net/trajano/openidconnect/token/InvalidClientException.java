package net.trajano.openidconnect.token;

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

    /**
     * 
     * @param type authorization type (e.g. Bearer or Basic)
     */
    public InvalidClientException(String type) {

        super(Response.noContent()
                .header(WWW_AUTHENTICATE, buildWwwAuthenticateHeader(type, null, null))
                .status(Status.UNAUTHORIZED)
                .build());
    }

    public InvalidClientException(String type, String errorDescription) {

        super(Response.noContent()
                .header(WWW_AUTHENTICATE, buildWwwAuthenticateHeader(type, errorDescription, null))
                .status(Status.UNAUTHORIZED)
                .build());

    }

    public InvalidClientException(String type, String errorDescription, URI errorUri) {

        super(Response.noContent()
                .header(WWW_AUTHENTICATE, buildWwwAuthenticateHeader(type, errorDescription, errorUri))
                .status(Status.UNAUTHORIZED)
                .build());

    }

    private static String buildWwwAuthenticateHeader(String type,
            String errorDescription,
            URI errorUri) {

        StringBuilder b = new StringBuilder(type).append(" error=\"invalid_client\"");
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
