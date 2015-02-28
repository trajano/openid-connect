package net.trajano.openidconnect.provider;

import java.util.Collection;

import net.trajano.openidconnect.core.Scope;
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
     * @param subject
     * @param clientId
     * @param scopes
     * @return
     */
    Userinfo getUserinfo(String subject,
            String clientId,
            Collection<Scope> scopes);
}
