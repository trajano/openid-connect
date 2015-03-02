package net.trajano.openidconnect.provider.ejb;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Random;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.ejb.Lock;
import javax.ejb.LockType;
import javax.ejb.Singleton;
import javax.ejb.Startup;

import net.trajano.openidconnect.crypto.Base64Url;
import net.trajano.openidconnect.crypto.JsonWebKey;
import net.trajano.openidconnect.crypto.JsonWebKeySet;
import net.trajano.openidconnect.crypto.RsaWebKey;
import net.trajano.openidconnect.provider.spi.KeyProvider;

/**
 * Used to generate the keys used by the application. These are in memory only
 * and only encrypt data that is in transit. There are multiple RSA signing keys
 * that are generated like Google and the key will be chosen based on time.
 */
@Singleton
@Startup
@Lock(LockType.READ)
public class DefaultKeyProvider implements KeyProvider {

    private static class SigningKey {

        /**
         * Encoded JOSE header.
         */
        private String encodedJoseHeader;

        private RSAPrivateKey privateKey;

    }

    private static final int NUMBER_OF_SIGNING_KEYS = 3;

    private Random random;

    private SecretKey secretKey;

    private JsonWebKey[] signingJwks;

    private SigningKey[] signingKeys;

    @Override
    public byte[] decrypt(final byte[] content) throws GeneralSecurityException {

        final Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(content);
    }

    @Override
    public byte[] encrypt(final byte[] content) throws GeneralSecurityException {

        final Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(content);
    }

    @Override
    public byte[] encrypt(final String content) throws GeneralSecurityException {

        final byte[] contentBytes = content.getBytes();
        return encrypt(contentBytes);
    }

    @PostConstruct
    public void generateKeys() {

        try {
            random = new SecureRandom();

            signingJwks = new JsonWebKey[NUMBER_OF_SIGNING_KEYS];
            signingKeys = new SigningKey[NUMBER_OF_SIGNING_KEYS];

            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            for (int i = 0; i < NUMBER_OF_SIGNING_KEYS; ++i) {
                final KeyPair keyPair = keyPairGenerator.generateKeyPair();

                final String keyId = nextEncodedToken();
                final RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
                final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

                final SigningKey d = new SigningKey();
                d.encodedJoseHeader = Base64Url.encodeUsAscii(String.format("{\"alg\":\"%s\",\"kid\":\"%s\"}", "RS256", keyId));
                d.privateKey = privateKey;
                signingKeys[i] = d;
                signingJwks[i] = new RsaWebKey(keyId, publicKey);

            }

            final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            secretKey = keyGenerator.generateKey();

        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        System.out.println("Keys initialized");
    }

    @Override
    public JsonWebKeySet getJwks() {

        final JsonWebKeySet jwks = new JsonWebKeySet();
        for (final JsonWebKey jwk : getSigningKeys()) {
            jwks.add(jwk);
        }
        return jwks;
    }

    public SecretKey getSecretKey() {

        return secretKey;
    }

    @Override
    public JsonWebKey[] getSigningKeys() {

        return signingJwks;
    }

    @Override
    @Lock(LockType.WRITE)
    public String nextEncodedToken() {

        final byte[] randomTokenBytes = new byte[16];
        random.nextBytes(randomTokenBytes);
        return Base64Url.encode(randomTokenBytes);
    }

    /**
     * Signs the content using JWT.
     */
    @Override
    public String sign(final byte[] content) throws GeneralSecurityException {

        final SigningKey signingKey = signingKeys[random.nextInt(signingKeys.length)];
        final StringBuilder b = new StringBuilder(signingKey.encodedJoseHeader).append('.')
                .append(Base64Url.encode(content));

        final Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(signingKey.privateKey);
        signature.update(b.toString()
                .getBytes());
        return b.append('.')
                .append(Base64Url.encode(signature.sign()))
                .toString();
    }

    /**
     * Signs the content using JWT.
     */
    @Override
    public String sign(final String content) throws GeneralSecurityException {

        final SigningKey signingKey = signingKeys[new Random().nextInt() % signingKeys.length];
        final StringBuilder b = new StringBuilder(signingKey.encodedJoseHeader).append('.')
                .append(Base64Url.encode(content));

        final Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(signingKey.privateKey);
        signature.update(b.toString()
                .getBytes());
        return b.append('.')
                .append(Base64Url.encode(signature.sign()))
                .toString();
    }
}
