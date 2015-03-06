package net.trajano.openidconnect.core;

import java.net.URI;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

/**
 * Open ID Connect Exception. This wraps an error response based on the data
 * provided
 * 
 * @author Archimedes
 */
public class OpenIdConnectException extends BadRequestException {

    /**
     * 
     */
    private static final long serialVersionUID = 7363379256768742855L;

    public OpenIdConnectException(TokenErrorCode error) {

        this(new ErrorResponse(error));
    }

    public OpenIdConnectException(TokenErrorCode error, String errorDescription) {

        this(new ErrorResponse(error, errorDescription));
    }

    public OpenIdConnectException(TokenErrorCode error, String errorDescription, URI errorUri) {

        this(new ErrorResponse(error, errorDescription, errorUri));
    }

    public OpenIdConnectException(ErrorResponse errorResponse) {

        super(Response.ok(errorResponse)
                .status(Status.BAD_REQUEST)
                .build());
    }
}
