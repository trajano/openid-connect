package net.trajano.openidconnect.internal;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.trajano.openidconnect.crypto.Encoding;
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

        if (JsonWebAlgorithm.isMac(header.getAlg())) {
            Mac mac = Mac.getInstance(JsonWebAlgorithm.toJca(header.getAlg()));
            mac.init(jwk.toJcaKey());
            mac.update(header.getEncoded());
            mac.update((byte) '.');
            mac.update(Encoding.base64urlEncode(payloadBytes)
                    .getBytes(CharSets.US_ASCII));
            payloads[1] = mac.doFinal();
        } else {
            final Signature signature = Signature.getInstance(JsonWebAlgorithm.toJca(header.getAlg()));
            signature.initSign((PrivateKey) jwk.toJcaKey());
            signature.update(header.getEncoded());
            signature.update((byte) '.');
            signature.update(Encoding.base64urlEncode(payloadBytes)
                    .getBytes(CharSets.US_ASCII));
            payloads[1] = signature.sign();

        }
        return payloads;
    }

    @Override
    public byte[][] buildJWEPayload(JoseHeader joseHeader,
            byte[] payloadBytes,
            JsonWebKey jwk) throws IOException,
            GeneralSecurityException {

        String macAlg = JsonWebAlgorithm.getMacAlg(joseHeader.getEnc());
        if (macAlg == null) {
            return buildNoMacJWEPayload(joseHeader, payloadBytes, jwk);
        } else {
            return buildJWEPayloadWithMac(joseHeader, payloadBytes, jwk, macAlg);
        }
    }

    private byte[][] buildJWEPayloadWithMac(JoseHeader joseHeader,
            byte[] payloadBytes,
            JsonWebKey jwk,
            String macAlg) throws IOException,
            GeneralSecurityException {

        final byte[][] payloads = new byte[4][];

        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        final int keySize = JsonWebAlgorithm.getKeySize(joseHeader.getEnc());
        keyGenerator.init(keySize);

        final SecretKey secretKey = keyGenerator.generateKey();
        final SecretKey macKey = keyGenerator.generateKey();

        ByteArrayOutputStream cekStream = new ByteArrayOutputStream();

        final Cipher cekCipher = Cipher.getInstance(JsonWebAlgorithm.toJca(joseHeader.getAlg()));
        cekCipher.init(Cipher.ENCRYPT_MODE, jwk.toJcaPublicKey());
        CipherOutputStream os = new CipherOutputStream(cekStream, cekCipher);
        os.write(macKey.getEncoded());
        os.write(secretKey.getEncoded());
        os.close();

        final byte[] encryptedCek = cekStream.toByteArray();
        payloads[0] = encryptedCek;

        final byte[] iv = new byte[JsonWebAlgorithm.getIvLen(joseHeader.getEnc())];
        random.nextBytes(iv);
        payloads[1] = iv;

        final int authenticationTagBits = 128;
        final Cipher contentCipher = Cipher.getInstance(JsonWebAlgorithm.toJca(joseHeader.getEnc()));

        final byte[] aad = joseHeader.getEncoded();
        if (JsonWebAlgorithm.isGcm(joseHeader.getEnc())) {
            final GCMParameterSpec spec = new GCMParameterSpec(authenticationTagBits, iv);
            contentCipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            contentCipher.updateAAD(aad);
        } else {
            final IvParameterSpec spec = new IvParameterSpec(iv);
            contentCipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        }
        byte[] cipherText = contentCipher.doFinal(payloadBytes);
        payloads[2] = cipherText;

        byte[] hmacValue = calculateMac(macKey, iv, cipherText, aad, macAlg);
        payloads[3] = new byte[authenticationTagBits / 8];
        System.arraycopy(hmacValue, 0, payloads[3], 0, authenticationTagBits / 8);
        return payloads;
    }

    public byte[][] buildNoMacJWEPayload(JoseHeader joseHeader,
            byte[] payloadBytes,
            JsonWebKey jwk) throws IOException,
            GeneralSecurityException {

        final byte[][] payloads = new byte[4][];

        final KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(JsonWebAlgorithm.getKeySize(joseHeader.getEnc()));

        final SecretKey secretKey = keyGenerator.generateKey();

        final byte[] cek = secretKey.getEncoded();

        final Cipher cekCipher = Cipher.getInstance(JsonWebAlgorithm.toJca(joseHeader.getAlg()));
        cekCipher.init(Cipher.ENCRYPT_MODE, jwk.toJcaPublicKey());
        final byte[] encryptedCek = cekCipher.doFinal(cek);

        payloads[0] = encryptedCek;

        final byte[] iv = new byte[JsonWebAlgorithm.getIvLen(joseHeader.getEnc())];
        random.nextBytes(iv);
        payloads[1] = iv;

        final int authenticationTagBits = 128;
        final Cipher contentCipher = Cipher.getInstance(JsonWebAlgorithm.toJca(joseHeader.getEnc()));

        if (JsonWebAlgorithm.isGcm(joseHeader.getEnc())) {
            final GCMParameterSpec spec = new GCMParameterSpec(authenticationTagBits, iv);
            contentCipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
            contentCipher.updateAAD(joseHeader.getEncoded());
        } else {
            final IvParameterSpec spec = new IvParameterSpec(iv);
            contentCipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        }

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
        final byte[] aad = jsonWebToken.getJoseHeaderEncoded()
                .getBytes(CharSets.US_ASCII);
        final PrivateKey privateKey = (PrivateKey) jwk.toJcaKey();
        final String enc = jsonWebToken.getEnc();

        final Cipher encryptionKeyCipher = Cipher.getInstance(JsonWebAlgorithm.toJca(jsonWebToken.getAlg()));
        encryptionKeyCipher.init(Cipher.DECRYPT_MODE, privateKey);

        final byte[] decryptedKey = encryptionKeyCipher.doFinal(encryptedKey);

        final String macAlg = JsonWebAlgorithm.getMacAlg(jsonWebToken.getEnc());
        if (macAlg == null) {
            return getNoMacJWEPayload(decryptedKey, initializationVector, cipherText, authenticationTag, aad, enc);
        } else {
            return getJWEPayloadWithMac(decryptedKey, initializationVector, cipherText, authenticationTag, aad, enc, macAlg);
        }

    }

    private byte[] getNoMacJWEPayload(final byte[] encryptionKey,
            final byte[] initializationVector,
            final byte[] cipherText,
            final byte[] authenticationTag,
            final byte[] aad,
            final String enc) throws NoSuchAlgorithmException,
            NoSuchPaddingException,
            InvalidKeyException,
            InvalidAlgorithmParameterException,
            IOException,
            IllegalBlockSizeException,
            BadPaddingException {

        final SecretKey contentEncryptionKey = new SecretKeySpec(encryptionKey, "AES");

        final Cipher contentCipher = Cipher.getInstance(JsonWebAlgorithm.toJca(enc));

        if (JsonWebAlgorithm.isGcm(enc)) {
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

    private byte[] getJWEPayloadWithMac(final byte[] encryptionKey,
            final byte[] initializationVector,
            final byte[] cipherText,
            final byte[] authenticationTag,
            final byte[] aad,
            final String enc,
            String macAlg) throws GeneralSecurityException,
            IOException {

        final int keyLength = JsonWebAlgorithm.getKeySize(enc) / 8;
        final int macLength = encryptionKey.length - keyLength;
        final SecretKey macKey = new SecretKeySpec(encryptionKey, 0, macLength, "AES");

        final SecretKey contentEncryptionKey = new SecretKeySpec(encryptionKey, macLength, keyLength, "AES");
        final Cipher contentCipher = Cipher.getInstance(JsonWebAlgorithm.toJca(enc));

        if (JsonWebAlgorithm.isGcm(enc)) {
            final GCMParameterSpec spec = new GCMParameterSpec(authenticationTag.length * 8, initializationVector);
            contentCipher.init(Cipher.DECRYPT_MODE, contentEncryptionKey, spec);
            contentCipher.updateAAD(aad);
        } else {
            final IvParameterSpec spec = new IvParameterSpec(initializationVector);
            contentCipher.init(Cipher.DECRYPT_MODE, contentEncryptionKey, spec);
        }
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(contentCipher.doFinal(cipherText));
        baos.close();

        byte[] hmacValue = calculateMac(macKey, initializationVector, cipherText, aad, macAlg);

        for (int i = 0; i < authenticationTag.length; ++i) {
            if (hmacValue[i] != authenticationTag[i]) {
                throw new GeneralSecurityException("MAC validation failed");
            }
        }

        return baos.toByteArray();
    }

    private byte[] calculateMac(final SecretKey macKey,
            final byte[] initializationVector,
            final byte[] cipherText,
            final byte[] aad,
            String macAlg) throws NoSuchAlgorithmException,
            InvalidKeyException {

        final Mac mac = Mac.getInstance(macAlg);
        mac.init(macKey);
        long bits = aad.length * 8;
        byte[] al = new byte[8];
        for (int i = 7; i >= 0; --i) {
            al[i] = (byte) (bits % 256);
            bits = bits / 256;
        }

        mac.update(aad);
        mac.update(initializationVector);
        mac.update(cipherText);
        byte[] hmacValue = mac.doFinal(al);
        return hmacValue;
    }

    @Override
    public byte[] getJWSPayload(JsonWebToken jsonWebToken,
            JsonWebKey jwk,
            String alg) throws GeneralSecurityException {

        if (JsonWebAlgorithm.isMac(alg)) {
            Mac mac = Mac.getInstance(JsonWebAlgorithm.toJca(alg));
            mac.init(jwk.toJcaKey());
            mac.update(jsonWebToken.getJoseHeaderEncoded()
                    .getBytes());
            mac.update((byte) '.');
            byte[] macValue = mac.doFinal(Encoding.base64urlEncode(jsonWebToken.getPayload(0))
                    .getBytes());
            if (!MessageDigest.isEqual(macValue, jsonWebToken.getPayload(1))) {
                throw new SignatureException("signature verification failed");
            }
        } else {
            final PublicKey signingKey = (PublicKey) jwk.toJcaPublicKey();

            final Signature signature = Signature.getInstance(JsonWebAlgorithm.toJca(alg));

            final byte[] jwtSignatureBytes = jsonWebToken.getPayload(1);

            signature.initVerify(signingKey);
            signature.update(jsonWebToken.getJoseHeaderEncoded()
                    .getBytes());
            signature.update((byte) '.');
            signature.update(Encoding.base64urlEncode(jsonWebToken.getPayload(0))
                    .getBytes());
            if (!signature.verify(jwtSignatureBytes)) {
                throw new SignatureException("signature verification failed");
            }
        }
        return jsonWebToken.getPayload(0);
    }
}
