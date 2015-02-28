package net.trajano.openidconnect.provider;

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

        this(clientManager.getRealmName());
    }

    public BearerTokenException(ClientManager clientManager, String errorCode) {

        this(clientManager.getRealmName(), errorCode);
    }

    public BearerTokenException(ClientManager clientManager, String errorCode, String errorDescription) {

        this(clientManager.getRealmName(), errorCode, errorDescription);
    }
}
