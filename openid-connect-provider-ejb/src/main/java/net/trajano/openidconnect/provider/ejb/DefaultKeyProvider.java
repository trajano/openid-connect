package net.trajano.openidconnect.provider.ejb;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.ejb.Singleton;
import javax.ejb.Startup;

import net.trajano.openidconnect.crypto.Base64Url;
import net.trajano.openidconnect.crypto.JsonWebKey;
import net.trajano.openidconnect.crypto.RsaWebKey;
import net.trajano.openidconnect.provider.KeyProvider;

/**
 * Used to generate the keys used by the application. These are in memory only
 * and only encrypt data that is in transit.
 */
@Singleton
@Startup
public class DefaultKeyProvider implements KeyProvider{

    /**
     * Encoded JOSE header.
     */
    private String encodedJoseHeader;

    /**
     * This is the JSON Web Key that is built from the key pair.
     */
    private JsonWebKey jwk;

    /**
     * Randomly generated key ID for the signing key
     */
    private UUID keyId;

    private RSAPrivateKey privateKey;

    private RSAPublicKey publicKey;

    private SecretKey secretKey;

    public byte[] decrypt(final byte[] content) throws GeneralSecurityException {

        final Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(content);
    }

    public byte[] encrypt(final byte[] content) throws GeneralSecurityException {

        final Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(content);
    }

    public byte[] encrypt(final String content) throws GeneralSecurityException {

        final byte[] contentBytes = content.getBytes();
        return encrypt(contentBytes);
    }

    @PostConstruct
    public void generateKeys() {

        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            final KeyPair keyPair = keyPairGenerator.generateKeyPair();

            keyId = UUID.randomUUID();

            privateKey = (RSAPrivateKey) keyPair.getPrivate();
            publicKey = (RSAPublicKey) keyPair.getPublic();
            jwk = new RsaWebKey(keyId.toString(), publicKey);

            final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            secretKey = keyGenerator.generateKey();

            encodedJoseHeader = Base64Url.encodeUsAscii(String.format("{\"alg\":\"%s\",\"kid\":\"%s\"}", "RS256", keyId));
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public JsonWebKey getJwk() {

        return jwk;
    }

    public String getKid() {

        return keyId.toString();
    }

    public RSAPrivateKey getPrivateKey() {

        return privateKey;
    }

    public PublicKey getPublicKey() {

        return publicKey;
    }

    public SecretKey getSecretKey() {

        return secretKey;
    }

    public String sign(final byte[] content) throws GeneralSecurityException {

        final StringBuilder b = new StringBuilder(encodedJoseHeader).append('.')
                .append(Base64Url.encode(content));

        final Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(b.toString()
                .getBytes());
        return b.append('.')
                .append(Base64Url.encode(signature.sign()))
                .toString();
    }
}
