package net.trajano.openidconnect.provider.spi;

import java.util.Set;

import net.trajano.openidconnect.provider.type.Scope;
import net.trajano.openidconnect.token.IdToken;
import net.trajano.openidconnect.userinfo.Userinfo;

/**
 * The user info provider
 *
 * @author Archimedes
 */
public interface UserinfoProvider {

    Set<String> claimsSupported();

    /**
     * Gets the user info for the specified subject limited by the clientId and
     * scopes specified.
     *
     * @param idToken
     *            ID Token
     * @return
     */
    Userinfo getUserinfo(IdToken idToken);

    /**
     * Scopes that are supported by the user info provider. This is added to
     * "openid"
     *
     * @return scopes supported.
     */
    Set<Scope> scopesSupported();
}
