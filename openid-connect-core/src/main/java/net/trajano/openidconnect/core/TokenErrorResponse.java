package net.trajano.openidconnect.core;

import java.net.URI;

import javax.xml.bind.annotation.XmlElement;

/**
 * The authorization server responds with an HTTP 400 (Bad Request) status code
 * (unless specified otherwise) .
 *
 * @see http://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse
 * @see http://tools.ietf.org/html/rfc6749#section-5.2
 * @author Archimedes Trajano
 */
public class TokenErrorResponse {

    public enum ErrorCode {

        /**
         *
         Client authentication failed (e.g., unknown client, no client
         * authentication included, or unsupported authentication method). The
         * authorization server MAY return an HTTP 401 (Unauthorized) status
         * code to indicate which HTTP authentication schemes are supported. If
         * the client attempted to authenticate via the "Authorization" request
         * header field, the authorization server MUST respond with an HTTP 401
         * (Unauthorized) status code and include the "WWW-Authenticate"
         * response header field matching the authentication scheme used by the
         * client.
         */
        invalid_client,

        /**
         * The provided authorization grant (e.g., authorization code, resource
         * owner credentials) or refresh token is invalid, expired, revoked,
         * does not match the redirection URI used in the authorization request,
         * or was issued to another client.
         */
        invalid_grant,
        /**
         * The request is missing a required parameter, includes an unsupported
         * parameter value (other than grant type), repeats a parameter,
         * includes multiple credentials, utilizes more than one mechanism for
         * authenticating the client, or is otherwise malformed.
         */
        invalid_request,

        /**
         * The requested scope is invalid, unknown, malformed, or exceeds the
         * scope granted by the resource owner.
         */
        invalid_scope,
        /**
         * The authenticated client is not authorized to use this authorization
         * grant type.
         */
        unauthorized_client,

        /**
         * The authorization grant type is not supported by the authorization
         * server.
         */
        unsupported_grant_type

    }

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
