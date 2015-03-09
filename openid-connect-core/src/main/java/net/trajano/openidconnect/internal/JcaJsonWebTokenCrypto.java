package net.trajano.openidconnect.internal;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

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
import net.trajano.openidconnect.crypto.JsonWebToken;
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

        final Signature signature = Signature.getInstance(JsonWebAlgorithm.toJca(jwk.getAlg()));
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
        keyGenerator.init(JsonWebAlgorithm.getKeySize(joseHeader.getEnc()));

        final SecretKey secretKey = keyGenerator.generateKey();

        final byte[] cek = secretKey.getEncoded();

        final Cipher cekCipher = Cipher.getInstance(JsonWebAlgorithm.toJca(joseHeader.getAlg()));
        cekCipher.init(Cipher.ENCRYPT_MODE, jwk.toJcaKey());
        final byte[] encryptedCek = cekCipher.doFinal(cek);

        payloads[0] = encryptedCek;

        final byte[] iv = new byte[JsonWebAlgorithm.getIvLen(joseHeader.getEnc())];
        random.nextBytes(iv);
        final int authenticationTagBits = 128;
        final Cipher contentCipher = Cipher.getInstance(JsonWebAlgorithm.toJca(joseHeader.getEnc()));

        if ("A128GCM".equals(joseHeader.getEnc()) || "A256GCM".equals(joseHeader.getEnc())) {
            final GCMParameterSpec spec = new GCMParameterSpec(authenticationTagBits, iv);
            contentCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), spec);
            contentCipher.updateAAD(joseHeader.getEncoded());
        } else {
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

    @Override
    public byte[] inflate(final byte[] compressed) throws IOException {

        final Inflater inflater = new Inflater(false);
        inflater.setInput(compressed);
        inflater.finished();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream(compressed.length);
        final byte[] buffer = new byte[1024];
        try {
            while (!inflater.finished()) {
                int len;
                len = inflater.inflate(buffer);
                baos.write(buffer, 0, len);
            }
            baos.close();
            return baos.toByteArray();
        } catch (DataFormatException e) {
            throw new IOException(e);
        }
    }

    @Override
    public byte[] deflate(final byte[] uncompressed) throws IOException {

        final Deflater deflater = new Deflater(9, false);
        deflater.setInput(uncompressed);
        deflater.finish();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream(uncompressed.length);
        final byte[] buffer = new byte[1024];
        while (!deflater.finished()) {
            final int len = deflater.deflate(buffer);
            baos.write(buffer, 0, len);
        }
        baos.close();
        return baos.toByteArray();
    }

    @Override
    public byte[] getJWEPayload(JsonWebToken jsonWebToken,
            JsonWebKey jwk) throws IOException,
            GeneralSecurityException {

        final byte[] encryptedKey = jsonWebToken.getPayload(0);
        final byte[] initializationVector = jsonWebToken.getPayload(1);
        final byte[] cipherText = jsonWebToken.getPayload(2);
        final byte[] authenticationTag = jsonWebToken.getPayload(3);
        final PrivateKey privateKey = (PrivateKey) jwk.toJcaKey();

        final Cipher encryptionKeyCipher = Cipher.getInstance(JsonWebAlgorithm.toJca((jsonWebToken.getAlg())));
        encryptionKeyCipher.init(Cipher.DECRYPT_MODE, privateKey);
        final byte[] decryptedKey = encryptionKeyCipher.doFinal(encryptedKey);

        final SecretKey contentEncryptionKey = new SecretKeySpec(decryptedKey, "AES");

        final byte[] aad = jsonWebToken.getJoseHeaderEncoded()
                .getBytes(CharSets.US_ASCII);

        final Cipher contentCipher = Cipher.getInstance(JsonWebAlgorithm.toJca(jsonWebToken.getEnc()));

        if (JsonWebAlgorithm.isGcm(jsonWebToken.getEnc())) {
            final GCMParameterSpec spec = new GCMParameterSpec(authenticationTag.length * 8, initializationVector);
            contentCipher.init(Cipher.DECRYPT_MODE, contentEncryptionKey, spec);
            contentCipher.updateAAD(aad);
        } else {
            final IvParameterSpec spec = new IvParameterSpec(initializationVector);
            contentCipher.init(Cipher.DECRYPT_MODE, contentEncryptionKey, spec);
        }
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(contentCipher.update(cipherText));
        baos.write(contentCipher.doFinal(authenticationTag));
        baos.close();
        return baos.toByteArray();
    }

    @Override
    public byte[] getJWSPayload(JsonWebToken jsonWebToken,
            JsonWebKey jwk,
            String alg) throws GeneralSecurityException {

        final PublicKey signingKey = (PublicKey) jwk.toJcaPublicKey();

        final Signature signature = Signature.getInstance(JsonWebAlgorithm.toJca(alg));

        final byte[] jwtSignatureBytes = jsonWebToken.getPayload(1);

        signature.initVerify(signingKey);
        signature.update(jsonWebToken.getJoseHeaderEncoded()
                .getBytes());
        signature.update((byte) '.');
        signature.update(Base64Url.encode(jsonWebToken.getPayload(0))
                .getBytes());
        if (!signature.verify(jwtSignatureBytes)) {
            throw new SignatureException("signature verification failed");
        }

        return jsonWebToken.getPayload(0);
    }
}
