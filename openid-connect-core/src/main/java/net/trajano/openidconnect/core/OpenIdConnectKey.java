package net.trajano.openidconnect.core;

/**
 * Registered Open ID Connect Keys. This unifies all the key string constants
 * defined in OpenID Connect specifications.
 *
 * @author Archimedes
 */
public final class OpenIdConnectKey {

    /**
     * OPTIONAL. Requested Authentication Context Class Reference values.
     * Space-separated string that specifies the acr values that the
     * Authorization Server is being requested to use for processing this
     * Authentication Request, with the values appearing in order of preference.
     * The Authentication Context Class satisfied by the authentication
     * performed is returned as the acr Claim Value, as specified in Section 2.
     * The acr Claim is requested as a Voluntary Claim by this parameter.
     */
    public static final String ACR_VALUES = "acr_values";

    /**
     * REQUIRED. OAuth 2.0 Client Identifier valid at the Authorization Server.
     */
    public static final String CLIENT_ID = "client_id";

    public static final String CLIENT_SECRET = "client_secret";
    public static final String CLAIMS = "claims";

    public static final String CODE = "code";

    /**
     * OPTIONAL. ASCII string value that specifies how the Authorization Server
     * displays the authentication and consent user interface pages to the
     * End-User. The defined values are:
     */
    public static final String DISPLAY = "display";

    /**
     * Error code. Possible values are in {@link ErrorCode}.
     */
    public static final String ERROR = "error";

    /**
     * OPTIONAL. Human-readable ASCII encoded text description of the error.
     */
    public static final String ERROR_DESCRIPTION = "error_description";

    /**
     * OPTIONAL. URI of a web page that includes additional information about
     * the error.
     */
    public static final String ERROR_URI = "error_uri";

    public static final String GRANT_TYPE = "grant_type";

    /**
     * <p>
     * OPTIONAL. ID Token previously issued by the Authorization Server being
     * passed as a hint about the End-User's current or past authenticated
     * session with the Client. If the End-User identified by the ID Token is
     * logged in or is logged in by the request, then the Authorization Server
     * returns a positive response; otherwise, it SHOULD return an error, such
     * as login_required. When possible, an id_token_hint SHOULD be present when
     * prompt=none is used and an invalid_request error MAY be returned if it is
     * not; however, the server SHOULD respond successfully when possible, even
     * if it is not present. The Authorization Server need not be listed as an
     * audience of the ID Token when it is used as an id_token_hint value.
     * </p>
     * <p>
     * If the ID Token received by the RP from the OP is encrypted, to use it as
     * an id_token_hint, the Client MUST decrypt the signed ID Token contained
     * within the encrypted ID Token. The Client MAY re-encrypt the signed ID
     * token to the Authentication Server using a key that enables the server to
     * decrypt the ID Token, and use the re-encrypted ID token as the
     * id_token_hint value.
     * </p>
     */
    public static final String ID_TOKEN_HINT = "id_token_hint";

    /**
     * OPTIONAL. Hint to the Authorization Server about the login identifier the
     * End-User might use to log in (if necessary). This hint can be used by an
     * RP if it first asks the End-User for their e-mail address (or other
     * identifier) and then wants to pass that value as a hint to the discovered
     * authorization service. It is RECOMMENDED that the hint value match the
     * value used for discovery. This value MAY also be a phone number in the
     * format specified for the phone_number Claim. The use of this parameter is
     * left to the OP's discretion.
     */
    public final static String LOGIN_HINT = "login_hint";

    /**
     * OPTIONAL. Maximum Authentication Age. Specifies the allowable elapsed
     * time in seconds since the last time the End-User was actively
     * authenticated by the OP. If the elapsed time is greater than this value,
     * the OP MUST attempt to actively re-authenticate the End-User. (The
     * max_age request parameter corresponds to the OpenID 2.0 PAPE
     * [OpenID.PAPE] max_auth_age request parameter.) When max_age is used, the
     * ID Token returned MUST include an auth_time Claim Value.
     */
    public static final String MAX_AGE = "max_age";

    /**
     * OPTIONAL. String value used to associate a Client session with an ID
     * Token, and to mitigate replay attacks. The value is passed through
     * unmodified from the Authentication Request to the ID Token. Sufficient
     * entropy MUST be present in the nonce values used to prevent attackers
     * from guessing values. For implementation notes, see Section 15.5.2.
     */
    public static final String NONCE = "nonce";

    /**
     * OPTIONAL. Space delimited, case sensitive list of ASCII string values
     * that specifies whether the Authorization Server prompts the End-User for
     * reauthentication and consent. The defined values are:
     */
    public static final String PROMPT = "prompt";

    /**
     * REQUIRED. Redirection URI to which the response will be sent. This URI
     * MUST exactly match one of the Redirection URI values for the Client
     * pre-registered at the OpenID Provider, with the matching performed as
     * described in Section 6.2.1 of [RFC3986] (Simple String Comparison). When
     * using this flow, the Redirection URI SHOULD use the https scheme;
     * however, it MAY use the http scheme, provided that the Client Type is
     * confidential, as defined in Section 2.1 of OAuth 2.0, and provided the OP
     * allows the use of http Redirection URIs in this case. The Redirection URI
     * MAY use an alternate scheme, such as one that is intended to identify a
     * callback into a native application.
     */
    public static final String REDIRECT_URI = "redirect_uri";

    public static final String REQUEST = "request";

    /**
     * OPTIONAL. Informs the Authorization Server of the mechanism to be used
     * for returning parameters from the Authorization Endpoint. This use of
     * this parameter is NOT RECOMMENDED when the Response Mode that would be
     * requested is the default mode specified for the Response Type.
     */
    public static final String RESPONSE_MODE = "response_mode";

    /**
     * REQUIRED. OAuth 2.0 Response Type value that determines the authorization
     * processing flow to be used, including what parameters are returned from
     * the endpoints used. When using the Authorization Code Flow, this value is
     * code.
     */
    public static final String RESPONSE_TYPE = "response_type";

    /**
     * REQUIRED. OpenID Connect requests MUST contain the openid scope value. If
     * the openid scope value is not present, the behavior is entirely
     * unspecified. Other scope values MAY be present. Scope values used that
     * are not understood by an implementation SHOULD be ignored. See Sections
     * 5.4 and 11 for additional scope values defined by this specification.
     */
    public static final String SCOPE = "scope";

    /**
     * An opaque value used to maintain state between the request and the
     * callback. Typically, Cross-Site Request Forgery (CSRF, XSRF) mitigation
     * is done by cryptographically binding the value of this parameter with a
     * browser cookie. This is REQUIRED if the Authorization Request included
     * the state parameter. Set to the value received from the Client.
     */
    public static final String STATE = "state";

    /**
     * OPTIONAL. End-User's preferred languages and scripts for the user
     * interface, represented as a space-separated list of BCP47 [RFC5646]
     * language tag values, ordered by preference. For instance, the value
     * "fr-CA fr en" represents a preference for French as spoken in Canada,
     * then French (without a region designation), followed by English (without
     * a region designation). An error SHOULD NOT result if some or all of the
     * requested locales are not supported by the OpenID Provider.
     */
    public static final String UI_LOCALES = "ui_locales";

    public static final String REFRESH_TOKEN = "refresh_token";

    private OpenIdConnectKey() {

    }
}
