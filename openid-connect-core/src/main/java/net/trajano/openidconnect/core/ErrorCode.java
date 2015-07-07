package net.trajano.openidconnect.core;

/**
 * Registered OpenID Connect error codes. This also include
 * <a href="http://tools.ietf.org/html/rfc6749#section-4.1.2.1">OAuth 2.0</a>
 * responses as well.
 *
 * @author Archimedes Trajano
 */
public enum ErrorCode {
        /**
         * The resource owner or authorization server denied the request.
         */
    access_denied,

        /**
         * The End-User is REQUIRED to select a session at the Authorization
         * Server. The End-User MAY be authenticated at the Authorization Server
         * with different associated accounts, but the End-User did not select a
         * session. This error MAY be returned when the prompt parameter value
         * in the Authentication Request is none, but the Authentication Request
         * cannot be completed without displaying a user interface to prompt for
         * a session to use.
         */
    account_selection_required,

        /**
         * The Authorization Server requires End-User consent. This error MAY be
         * returned when the prompt parameter value in the Authentication
         * Request is none, but the Authentication Request cannot be completed
         * without displaying a user interface for End-User consent.
         */
    consent_required,

        /**
         * The Authorization Server requires End-User interaction of some form
         * to proceed. This error MAY be returned when the prompt parameter
         * value in the Authentication Request is none, but the Authentication
         * Request cannot be completed without displaying a user interface for
         * End-User interaction.
         */
    interaction_required,

        /**
         * Client authentication failed (e.g., unknown client, no client
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
         * The request is missing a required parameter, includes an invalid
         * parameter value, includes a parameter more than once, or is otherwise
         * malformed.
         */
    invalid_request,

        /**
         * The request parameter contains an invalid Request Object.
         */
    invalid_request_object,

        /**
         * The request_uri in the Authorization Request returns an error or
         * contains invalid data.
         */
    invalid_request_uri,

        /**
         * The requested scope is invalid, unknown, malformed, or exceeds the
         * scope granted by the resource owner.
         */
    invalid_scope,

        /**
         * The Authorization Server requires End-User authentication. This error
         * MAY be returned when the prompt parameter value in the Authentication
         * Request is none, but the Authentication Request cannot be completed
         * without displaying a user interface for End-User authentication.
         */
    login_required,

        /**
         * The OP does not support use of the registration parameter defined in
         * Section 7.2.1.
         */
    registration_not_supported,

        /**
         * The OP does not support use of the request parameter defined in
         * Section 6.
         */
    request_not_supported,

        /**
         * The OP does not support use of the request_uri parameter defined in
         * Section 6.
         */
    request_uri_not_supported,

        /**
         * The authorization server encountered an unexpected condition that
         * prevented it from fulfilling the request. (This error code is needed
         * because a 500 Internal Server Error HTTP status code cannot be
         * returned to the client via an HTTP redirect.)
         */
    server_error,

        /**
         * The authorization server is currently unable to handle the request
         * due to a temporary overloading or maintenance of the server. (This
         * error code is needed because a 503 Service Unavailable HTTP status
         * code cannot be returned to the client via an HTTP redirect.)
         */
    temporarily_unavailable,

        /**
         * The client is not authorized to request an authorization code using
         * this method.
         */
    unauthorized_client,

        /**
         * The authorization grant type is not supported by the authorization
         * server.
         */
    unsupported_grant_type,

        /**
         * The authorization server does not support obtaining an authorization
         * code using this method.
         */
    unsupported_response_type

}
