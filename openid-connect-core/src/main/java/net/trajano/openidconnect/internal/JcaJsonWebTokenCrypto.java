package net.trajano.openidconnect.internal;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.trajano.openidconnect.crypto.Base64Url;
import net.trajano.openidconnect.crypto.JoseHeader;
import net.trajano.openidconnect.crypto.JsonWebAlgorithm;
import net.trajano.openidconnect.crypto.JsonWebKey;
import net.trajano.openidconnect.crypto.JsonWebTokenCrypto;

public class JcaJsonWebTokenCrypto implements JsonWebTokenCrypto {

    private static final JcaJsonWebTokenCrypto INSTANCE = new JcaJsonWebTokenCrypto();

    public static JsonWebTokenCrypto getInstance() {

        return INSTANCE;
    }

    private final SecureRandom random = new SecureRandom();

    @Override
    public byte[][] buildJWSPayload(JoseHeader header,
            byte[] payloadBytes,
            JsonWebKey jwk) throws GeneralSecurityException {

        final byte[][] payloads = new byte[2][];
        payloads[0] = payloadBytes;
        final StringBuilder b = new StringBuilder(Base64Url.encode(header.toString())).append('.')
                .append(Base64Url.encode(payloadBytes));

        final Signature signature = Signature.getInstance(header.getAlg()
                .toJca());
        signature.initSign((PrivateKey) jwk.toJcaKey());
        signature.update(b.toString()
                .getBytes(CharSets.US_ASCII));
        payloads[1] = signature.sign();
        return payloads;
    }

    @Override
    public byte[][] buildJWEPayload(JoseHeader joseHeader,
            byte[] payloadBytes,
            JsonWebKey jwk) throws IOException,
            GeneralSecurityException {

        final byte[][] payloads = new byte[4][];

        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(joseHeader.getEnc()
                .getBits());
        final SecretKey secretKey = keyGenerator.generateKey();

        final byte[] cek = secretKey.getEncoded();

        final Cipher cekCipher = Cipher.getInstance(joseHeader.getAlg()
                .toJca());
        cekCipher.init(Cipher.ENCRYPT_MODE, jwk.toJcaKey());
        final byte[] encryptedCek = cekCipher.doFinal(cek);

        payloads[0] = encryptedCek;

        final byte[] iv;
        final int authenticationTagBits = 128;
        final Cipher contentCipher = Cipher.getInstance(joseHeader.getEnc()
                .toJca());

        if (joseHeader.getEnc() == JsonWebAlgorithm.A128GCM || joseHeader.getEnc() == JsonWebAlgorithm.A256GCM) {
            iv = new byte[96];
            random.nextBytes(iv);
            final GCMParameterSpec spec = new GCMParameterSpec(authenticationTagBits, iv);
            contentCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), spec);
            contentCipher.updateAAD(joseHeader.getEncoded());
        } else {
            iv = new byte[16];
            random.nextBytes(iv);
            final IvParameterSpec spec = new IvParameterSpec(iv);
            contentCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), spec);
        }
        payloads[1] = iv;

        final ByteBuffer cipherTextAndAuthenticationTag = ByteBuffer.wrap(contentCipher.doFinal(payloadBytes));

        payloads[2] = new byte[cipherTextAndAuthenticationTag.capacity() - authenticationTagBits / 8];
        payloads[3] = new byte[authenticationTagBits / 8];

        cipherTextAndAuthenticationTag.get(payloads[2])
                .get(payloads[3]);
        return payloads;
    }
}
