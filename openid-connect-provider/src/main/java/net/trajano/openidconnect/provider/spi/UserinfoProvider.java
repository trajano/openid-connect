package net.trajano.openidconnect.provider.spi;

import net.trajano.openidconnect.core.Scope;
import net.trajano.openidconnect.token.IdToken;
import net.trajano.openidconnect.userinfo.Userinfo;

/**
 * The user info provider
 *
 * @author Archimedes
 */
public interface UserinfoProvider {

    /**
     * Scopes that are supported by the user info provider. This is added to
     * "openid"
     * 
     * @return scopes supported.
     */
    Scope[] scopesSupported();

    /**
     * Gets the user info for the specified subject limited by the clientId and
     * scopes specified.
     *
     * @param idToken
     *            ID Token
     * @return
     */
    Userinfo getUserinfo(IdToken idToken);

    String[] claimsSupported();
}
