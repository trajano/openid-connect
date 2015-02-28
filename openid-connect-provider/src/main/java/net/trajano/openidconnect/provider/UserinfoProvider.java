package net.trajano.openidconnect.provider;

import net.trajano.openidconnect.core.TokenResponse;
import net.trajano.openidconnect.core.Userinfo;

/**
 * The user info provider
 * 
 * @author Archimedes
 */
public interface UserinfoProvider {

    /**
     * Gets the user info for the specified subject limited by the clientId and
     * scopes specified.
     * 
     * @param tokenResponse
     *            access token response.
     * @return
     */
    Userinfo getUserinfo(TokenResponse tokenResponse);
}
