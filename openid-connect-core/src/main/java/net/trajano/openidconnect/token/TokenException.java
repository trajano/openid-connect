package net.trajano.openidconnect.token;

import java.net.URI;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

public class TokenException extends BadRequestException {

    /**
     * 
     */
    private static final long serialVersionUID = 7363379256768742855L;

    public TokenException(TokenErrorCode error) {

        super(Response.ok(new TokenErrorResponse(error))
                .status(Status.BAD_REQUEST)
                .build());
    }

    public TokenException(TokenErrorCode error, String errorDescription) {

        super(Response.ok(new TokenErrorResponse(error, errorDescription))
                .status(Status.BAD_REQUEST)
                .build());
    }

    public TokenException(TokenErrorCode error, String errorDescription, URI errorUri) {

        super(Response.ok(new TokenErrorResponse(error, errorDescription))
                .status(Status.BAD_REQUEST)
                .build());
    }
}
