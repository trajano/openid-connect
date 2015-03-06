package net.trajano.openidconnect.auth;

public enum Display {
    /**
     * The Authorization Server SHOULD display the authentication and
     * consent UI consistent with a full User Agent page view. If the
     * display parameter is not specified, this is the default display mode.
     */
    page,
    /**
     * The Authorization Server SHOULD display the authentication and
     * consent UI consistent with a popup User Agent window. The popup User
     * Agent window should be of an appropriate size for a login-focused
     * dialog and should not obscure the entire window that it is popping up
     * over.
     */
    popup,
    /**
     * The Authorization Server SHOULD display the authentication and
     * consent UI consistent with a device that leverages a touch interface.
     */
    touch,
    /**
     * The Authorization Server SHOULD display the authentication and
     * consent UI consistent with a "feature phone" type display.
     */
    wap
}