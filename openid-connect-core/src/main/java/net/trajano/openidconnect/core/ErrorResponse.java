package net.trajano.openidconnect.core;

import java.net.URI;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * Error response. This holds the data that gets sent either as a JSON object or
 * query parameters depending on the exception. The authorization server
 * responds with an HTTP 400 (Bad Request) status code (unless specified
 * otherwise). This can be sent
 *
 * @see http://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse
 * @see http://tools.ietf.org/html/rfc6749#section-5.2
 * @author Archimedes Trajano
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ErrorResponse {

    /**
     * REQUIRED. A single ASCII [USASCII] error code.
     */
    @XmlElement(required = true)
    private ErrorCode error;

    /**
     * OPTIONAL. Human-readable ASCII [USASCII] text providing additional
     * information, used to assist the client developer in understanding the
     * error that occurred. Values for the "error_description" parameter MUST
     * NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E.
     */
    @XmlElement(name = "error_description")
    private String errorDescription;

    /**
     * OPTIONAL. A URI identifying a human-readable web page with information
     * about the error, used to provide the client developer with additional
     * information about the error. Values for the "error_uri" parameter MUST
     * conform to the URI-reference syntax and thus MUST NOT include characters
     * outside the set %x21 / %x23-5B / %x5D-7E.
     */
    @XmlElement(name = "error_uri")
    private URI errorUri;

    public ErrorResponse() {

    }

    public ErrorResponse(final ErrorCode error) {

        this.error = error;
    }

    public ErrorResponse(final ErrorCode error, final String errorDescription) {

        this(error);
        this.errorDescription = errorDescription;
    }

    public ErrorResponse(final ErrorCode error, final String errorDescription, final URI errorUri) {

        this(error, errorDescription);
        this.errorUri = errorUri;
    }

    public ErrorCode getError() {

        return error;
    }

    public String getErrorDescription() {

        return errorDescription;
    }

    public URI getErrorUri() {

        return errorUri;
    }

    public void setError(final ErrorCode error) {

        this.error = error;
    }

    public void setErrorDescription(final String errorDescription) {

        this.errorDescription = errorDescription;
    }

    public void setErrorUri(final URI errorUri) {

        this.errorUri = errorUri;
    }
}
