package net.trajano.openidconnect.core;

import java.net.URI;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.core.MediaType;
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

    public OpenIdConnectException(final ErrorCode error) {

        this(new ErrorResponse(error));
    }

    public OpenIdConnectException(final ErrorCode error, final String errorDescription) {

        this(new ErrorResponse(error, errorDescription));
    }

    public OpenIdConnectException(final ErrorCode error, final String errorDescription, final URI errorUri) {

        this(new ErrorResponse(error, errorDescription, errorUri));
    }

    public OpenIdConnectException(final ErrorResponse errorResponse) {

        super(Response.ok(errorResponse)
                .type(MediaType.APPLICATION_JSON)
                .status(Status.BAD_REQUEST)
                .build());
    }
}
