package net.trajano.openidconnect.auth;

/**
 * <p>
 * An Authentication Error Response is an OAuth 2.0 Authorization Error Response
 * message returned from the OP's Authorization Endpoint in response to the
 * Authorization Request message sent by the RP.
 * </p>
 * <p>
 * If the End-User denies the request or the End-User authentication fails, the
 * OP (Authorization Server) informs the RP (Client) by using the Error Response
 * parameters defined in Section 4.1.2.1 of OAuth 2.0 [RFC6749]. (HTTP errors
 * unrelated to RFC 6749 are returned to the User Agent using the appropriate
 * HTTP status code.)
 * </p>
 * <p>
 * Unless the Redirection URI is invalid, the Authorization Server returns the
 * Client to the Redirection URI specified in the Authorization Request with the
 * appropriate error and state parameters. Other parameters SHOULD NOT be
 * returned.
 * </p>
 *
 * @author Archimedes Trajano
 * @see http://openid.net/specs/openid-connect-core-1_0.html#AuthError
 */
public final class AuthenticationErrorResponseParam {

    private AuthenticationErrorResponseParam() {

    }

}
