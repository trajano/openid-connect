package net.trajano.openidconnect.provider.spi;

import java.net.URI;

public interface ClientManager {

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
     * Checks if the client secret matches what is expected for the client ID.
     * 
     * @param clientId
     *            client ID
     * @param clientSecret
     *            client secret
     * @return <code>true</code> if the client secret matches what is expected
     *         for the client ID.
     */
    boolean authenticateClient(String clientId,
            String clientSecret);

    /**
     * Checks if the client secret matches what is expected for the client ID.
     * 
     * @param authorization
     *            Authorization header value including "Basic"
     * @return <code>true</code> if the client secret matches what is expected
     *         for the client ID.
     */
    boolean authenticateClient(String authorization);

    /**
     * The issuer URI. This is also used as the realm.
     * 
     * @return
     */
    URI getIssuer();
}
