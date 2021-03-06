package net.trajano.openidconnect.provider.spi;

import javax.ejb.Local;

import net.trajano.openidconnect.crypto.JsonWebKeySet;

/**
 * Used to generate the keys used by the application. These are in memory only
 * and only encrypt data that is in transit.
 */
@Local
public interface KeyProvider {

    /**
     * JWKS containing only signature validation keys.
     * 
     * @return
     */
    JsonWebKeySet getJwks();

    /**
     * JWKS containing the private keys.
     * 
     * @return
     */
    JsonWebKeySet getPrivateJwks();

    /**
     * Returns the Key ID for the secret key. Used as the ETag for caching.
     * 
     * @return
     */
    String getSecretKeyId();

    /**
     * Constructs a random token. The tokens are not required to be
     * cryptograhically secure.
     * 
     * @return random token string.
     */
    String nextEncodedToken();

}
