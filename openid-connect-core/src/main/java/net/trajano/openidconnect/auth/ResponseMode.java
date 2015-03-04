package net.trajano.openidconnect.auth;

public enum ResponseMode {
    /**
     * In this mode, Authorization Response parameters are encoded in the query
     * string added to the redirect_uri when redirecting back to the Client.
     */
    query,
    /**
     * In this mode, Authorization Response parameters are encoded in the
     * fragment added to the redirect_uri when redirecting back to the Client.
     */
    fragment, form_post
}
