package net.trajano.openidconnect.provider.spi;

import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

public class BearerTokenException extends NotAuthorizedException {

    /**
     * 
     */
    private static final long serialVersionUID = -8057706014764267842L;

    public BearerTokenException(String realm) {

        super(Response.status(Status.UNAUTHORIZED)
                .header("WWW-Authenticate", String.format("Bearer realm=\"%s\"", realm)));
    }

    public BearerTokenException(String realm, String errorCode) {

        super(Response.status(Status.UNAUTHORIZED)
                .header("WWW-Authenticate", String.format("Bearer realm=\"%s\", error=\"%s\"", realm, errorCode)));
    }

    public BearerTokenException(String realm, String errorCode, String errorDescription) {

        super(Response.status(Status.UNAUTHORIZED)
                .header("WWW-Authenticate", String.format("Bearer realm=\"%s\", error=\"%s\", error_description=\"%s\"", realm, errorCode, errorDescription)));
    }

    public BearerTokenException(ClientManager clientManager) {

        this(clientManager.getIssuer().toASCIIString());
    }

    public BearerTokenException(ClientManager clientManager, String errorCode) {

        this(clientManager.getIssuer().toASCIIString(), errorCode);
    }

    public BearerTokenException(ClientManager clientManager, String errorCode, String errorDescription) {

        this(clientManager.getIssuer().toASCIIString(), errorCode, errorDescription);
    }
}
