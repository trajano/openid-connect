package net.trajano.openidconnect.provider.spi;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;

import javax.crypto.SecretKey;
import javax.ejb.Local;

import net.trajano.openidconnect.crypto.JsonWebKey;

/**
 * Used to generate the keys used by the application. These are in memory only
 * and only encrypt data that is in transit.
 */
@Local
public interface KeyProvider {

    byte[] decrypt(final byte[] content) throws GeneralSecurityException;

    byte[] encrypt(final byte[] content) throws GeneralSecurityException;

    byte[] encrypt(final String content) throws GeneralSecurityException;

    JsonWebKey getJwk();

    String getKid();

    RSAPrivateKey getPrivateKey();

    PublicKey getPublicKey();

    SecretKey getSecretKey();

    String sign(final byte[] content) throws GeneralSecurityException;
}
