package net.trajano.openidconnect.core;

/**
 * <p>
 * OpenID Connect Clients use scope values as defined in 3.3 of OAuth 2.0
 * [RFC6749] to specify what access privileges are being requested for Access
 * Tokens. The scopes associated with Access Tokens determine what resources
 * will be available when they are used to access OAuth 2.0 protected endpoints.
 * For OpenID Connect, scopes can be used to request that specific sets of
 * information be made available as Claim Values. This specification describes
 * only the scope values used by OpenID Connect.
 * </p>
 * <p>
 * OpenID Connect allows additional scope values to be defined and used. Scope
 * values used that are not understood by an implementation SHOULD be ignored.
 * </p>
 * <p>
 * Claims requested by the following scopes are treated by Authorization Servers
 * as Voluntary Claims.
 * </p>
 */
public enum Scope {
    /**
     * OPTIONAL. This scope value requests access to the address Claim.
     */
    address,
    /**
     * OPTIONAL. This scope value requests access to the email and
     * email_verified Claims.
     */
    email,
    /**
     * OPTIONAL. This scope value requests that an OAuth 2.0 Refresh Token be
     * issued that can be used to obtain an Access Token that grants access to
     * the End-User's UserInfo Endpoint even when the End-User is not present
     * (not logged in).
     */
    offline_access,
    /**
     * REQUIRED. Informs the Authorization Server that the Client is making an
     * OpenID Connect request. If the openid scope value is not present, the
     * behavior is entirely unspecified.
     */
    openid,
    /**
     * OPTIONAL. This scope value requests access to the phone_number and
     * phone_number_verified Claims.
     */
    phone,
    /**
     * OPTIONAL. This scope value requests access to the End-User's default
     * profile Claims, which are: name, family_name, given_name, middle_name,
     * nickname, preferred_username, profile, picture, website, gender,
     * birthdate, zoneinfo, locale, and updated_at.
     */
    profile

}
