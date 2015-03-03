package net.trajano.openidconnect.provider.spi;

import java.security.GeneralSecurityException;

import javax.ejb.Local;

import net.trajano.openidconnect.crypto.JsonWebKeySet;

/**
 * Used to generate the keys used by the application. These are in memory only
 * and only encrypt data that is in transit.
 */
@Local
public interface KeyProvider {

    byte[] decrypt(final byte[] content) throws GeneralSecurityException;

    byte[] encrypt(final byte[] content) throws GeneralSecurityException;

    byte[] encrypt(final String content) throws GeneralSecurityException;

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

    String nextEncodedToken();

    String sign(final byte[] content) throws GeneralSecurityException;

    String sign(final String content) throws GeneralSecurityException;
}
