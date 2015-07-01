package net.trajano.openidconnect.provider.ejb;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

import javax.annotation.PostConstruct;
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

    /**
     * Number of signing keys to generate.
     */
    private static final int NUMBER_OF_SIGNING_KEYS = 3;

    private JsonWebKeySet jwks;

    private JsonWebKeySet privateJwks;

    /**
     * This random number generator is not required to be cryptographically
     * secure.
     */
    private Random rng = ThreadLocalRandom.current();

    private SecretKey secretKey;

    private String secretKeyId;

    @PostConstruct
    public void generateKeys() {

        try {
            jwks = new JsonWebKeySet();
            privateJwks = new JsonWebKeySet();

            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            for (int i = 0; i < NUMBER_OF_SIGNING_KEYS; ++i) {
                final KeyPair keyPair = keyPairGenerator.generateKeyPair();

                final String keyId = nextEncodedToken();
                final RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
                final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

                final JsonWebKey jwk = new RsaWebKey(keyId, publicKey);
                jwk.setAlg(JsonWebAlgorithm.RS256);

                jwks.add(jwk);

                final JsonWebKey privateJwk = new RsaWebKey(keyId, privateKey);
                privateJwk.setAlg(JsonWebAlgorithm.RS256);
                privateJwks.add(privateJwk);

            }

            final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            secretKey = keyGenerator.generateKey();
            final OctWebKey secretJwk = new OctWebKey(secretKey, JsonWebAlgorithm.A256CBC);
            secretKeyId = nextEncodedToken();
            secretJwk.setKid(secretKeyId);
            privateJwks.add(secretJwk);

        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Lock(LockType.READ)
    public JsonWebKeySet getJwks() {

        return jwks;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Lock(LockType.READ)
    public JsonWebKeySet getPrivateJwks() {

        return privateJwks;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Lock(LockType.READ)
    public String getSecretKeyId() {

        return secretKeyId;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Lock(LockType.WRITE)
    public String nextEncodedToken() {

        final byte[] randomTokenBytes = new byte[16];
        rng.nextBytes(randomTokenBytes);
        return Encoding.base64urlEncode(randomTokenBytes);
    }

}
