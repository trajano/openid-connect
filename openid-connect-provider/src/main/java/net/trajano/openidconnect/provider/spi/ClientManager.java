package net.trajano.openidconnect.provider.spi;

import java.net.URI;

public interface ClientManager {

    /**
     * Checks if the client secret matches what is expected for the client ID.
     *
     * @param clientId
     *            client ID
     * @param clientSecret
     *            client secret
     * @return returns the authenticated client ID.
     */
    String authenticateClient(String clientId,
            String clientSecret);

    /**
     * Checks if the redirect URI is valid for a given client ID.
     *
     * @param clientId
     *            client ID
     * @param redirectUri
     *            redirect URI
     * @return <code>true</code> if the redirect URI is valid for the given
     *         client ID.
     */
    boolean isRedirectUriValidForClient(String clientId,
            URI redirectUri);

    /**
     * Checks if the client ID specified has implicit consent.
     * 
     * @param clientId
     * @return
     */
    boolean isImplicitConsent(String clientId);

    boolean isPostLogoutRedirectUriValidForClient(String azp,
            URI postLogoutRedirectUri);
}
