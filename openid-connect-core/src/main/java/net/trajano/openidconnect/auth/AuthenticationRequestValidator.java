package net.trajano.openidconnect.auth;

/**
 * <p>
 * <a href=
 * "http://openid.net/specs/openid-connect-core-1_0.html#AuthRequestValidation">
 * Authorization request validation/a>. The Authorization Server MUST validate
 * the request received as follows:
 * </p>
 * <ul>
 * <li>The Authorization Server MUST validate all the OAuth 2.0 parameters
 * according to the OAuth 2.0 specification.</li>
 * <li>Verify that a scope parameter is present and contains the openid scope
 * value. (If no openid scope value is present, the request may still be a valid
 * OAuth 2.0 request, but is not an OpenID Connect request.)</li>
 * <li>The Authorization Server MUST verify that all the REQUIRED parameters are
 * present and their usage conforms to this specification.</li>
 * <li>If the sub (subject) Claim is requested with a specific value for the ID
 * Token, the Authorization Server MUST only send a positive response if the
 * End-User identified by that sub value has an active session with the
 * Authorization Server or has been Authenticated as a result of the request.
 * The Authorization Server MUST NOT reply with an ID Token or Access Token for
 * a different user, even if they have an active session with the Authorization
 * Server. Such a request can be made either using an id_token_hint parameter or
 * by requesting a specific Claim Value as described in Section 5.5.1, if the
 * claims parameter is supported by the implementation.</li>
 * </ul>
 * <p>
 * As specified in OAuth 2.0 [RFC6749], Authorization Servers SHOULD ignore
 * unrecognized request parameters.
 * </p>
 * <p>
 * If the Authorization Server encounters any error, it MUST return an error
 * response, per Section 3.1.2.6.
 * </p>
 *
 * @author Archimedes
 */
public class AuthenticationRequestValidator {

}
