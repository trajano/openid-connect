package net.trajano.openidconnect.provider.spi;

import java.security.GeneralSecurityException;

import javax.ejb.Local;

import net.trajano.openidconnect.crypto.JsonWebKey;
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

    JsonWebKey[] getSigningKeys();
    JsonWebKeySet getJwks();

    String sign(final byte[] content) throws GeneralSecurityException;
    String sign(final String content) throws GeneralSecurityException;
    
    String nextToken();
}
