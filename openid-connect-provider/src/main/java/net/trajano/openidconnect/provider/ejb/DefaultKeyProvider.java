package net.trajano.openidconnect.provider.ejb;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
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

import net.trajano.openidconnect.crypto.Encoding;
import net.trajano.openidconnect.crypto.JsonWebAlgorithm;
import net.trajano.openidconnect.crypto.JsonWebKey;
import net.trajano.openidconnect.crypto.JsonWebKeySet;
import net.trajano.openidconnect.crypto.OctWebKey;
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

            signingKeys = new SigningKey[NUMBER_OF_SIGNING_KEYS];

            jwks = new JsonWebKeySet();
            privateJwks = new JsonWebKeySet();

            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            for (int i = 0; i < NUMBER_OF_SIGNING_KEYS; ++i) {
                final KeyPair keyPair = keyPairGenerator.generateKeyPair();

                final String keyId = nextEncodedToken();
                final RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
                final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

                final SigningKey d = new SigningKey();
                d.encodedJoseHeader = Encoding.base64EncodeAscii(String.format("{\"alg\":\"%s\",\"kid\":\"%s\"}", "RS256", keyId));
                d.privateKey = privateKey;
                signingKeys[i] = d;

                JsonWebKey jwk = new RsaWebKey(keyId, publicKey);
                jwk.setAlg(JsonWebAlgorithm.RS256);

                jwks.add(jwk);

                JsonWebKey privateJwk = new RsaWebKey(keyId, privateKey);
                privateJwk.setAlg(JsonWebAlgorithm.RS256);
                privateJwks.add(privateJwk);

            }

            final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            secretKey = keyGenerator.generateKey();
            OctWebKey secretJwk = new OctWebKey(secretKey, JsonWebAlgorithm.A256CBC);
            secretKeyId = nextEncodedToken();
            secretJwk.setKid(secretKeyId);
            privateJwks.add(secretJwk);

        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private String secretKeyId;

    @Override
    public JsonWebKeySet getJwks() {

        return jwks;
    }

    private JsonWebKeySet jwks;

    private JsonWebKeySet privateJwks;

    public SecretKey getSecretKey() {

        return secretKey;
    }

    @Override
    @Lock(LockType.WRITE)
    public String nextEncodedToken() {

        final byte[] randomTokenBytes = new byte[16];
        random.nextBytes(randomTokenBytes);
        return Encoding.base64urlEncode(randomTokenBytes);
    }

    /**
     * Signs the content using JWT.
     */
    @Override
    @Deprecated
    public String sign(final byte[] content) throws GeneralSecurityException {

        final SigningKey signingKey = signingKeys[random.nextInt(signingKeys.length)];
        final StringBuilder b = new StringBuilder(signingKey.encodedJoseHeader).append('.')
                .append(Encoding.base64urlEncode(content));

        final Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(signingKey.privateKey);
        signature.update(b.toString()
                .getBytes());
        return b.append('.')
                .append(Encoding.base64urlEncode(signature.sign()))
                .toString();
    }

    /**
     * Signs the content using JWT.
     */
    @Override
    public String sign(final String content) throws GeneralSecurityException {

        final SigningKey signingKey = signingKeys[new Random().nextInt() % signingKeys.length];
        final StringBuilder b = new StringBuilder(signingKey.encodedJoseHeader).append('.')
                .append(Encoding.base64UrlEncode(content));

        final Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(signingKey.privateKey);
        signature.update(b.toString()
                .getBytes());
        return b.append('.')
                .append(Encoding.base64urlEncode(signature.sign()))
                .toString();
    }

    @Override
    public JsonWebKeySet getPrivateJwks() {

        return privateJwks;
    }

    @Override
    public String getSecretKeyId() {

        return secretKeyId;
    }
}
