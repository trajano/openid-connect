package net.trajano.openidconnect.auth;

public enum Prompt {

    /**
     * The Authorization Server SHOULD prompt the End-User for consent
     * before returning information to the Client. If it cannot obtain
     * consent, it MUST return an error, typically consent_required.
     */
    consent,

    /**
     * The Authorization Server SHOULD prompt the End-User for
     * reauthentication. If it cannot reauthenticate the End-User, it MUST
     * return an error, typically login_required.
     */
    login,

    /**
     * The Authorization Server MUST NOT display any authentication or
     * consent user interface pages. An error is returned if an End-User is
     * not already authenticated or the Client does not have pre-configured
     * consent for the requested Claims or does not fulfill other conditions
     * for processing the request. The error code will typically be
     * login_required, interaction_required, or another code defined in
     * Section 3.1.2.6. This can be used as a method to check for existing
     * authentication and/or consent.
     */
    none,

    /**
     * The Authorization Server SHOULD prompt the End-User to select a user
     * account. This enables an End-User who has multiple accounts at the
     * Authorization Server to select amongst the multiple accounts that
     * they might have current sessions for. If it cannot obtain an account
     * selection choice made by the End-User, it MUST return an error,
     * typically account_selection_required.
     */
    select_account

}