package net.trajano.openidconnect.internal;

import java.security.GeneralSecurityException;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.json.Json;
import javax.json.JsonObjectBuilder;

import net.trajano.openidconnect.crypto.KeyType;
import net.trajano.openidconnect.crypto.NamedEllipticCurve;

public class JcaJsonWebAlgorithm {

    /**
     * This is the mapping object that stores the encryption algorithm data. It
     * leverages the fact that the JsonObject is a map where the order is
     * guaranteed.
     */
    private final JsonObjectBuilder encsBuilder = Json.createObjectBuilder();

    /**
     * This is the mapping object that stores the key exchange algorithm data. It
     * leverages the fact that the JsonObject is a map where the order is
     * guaranteed.
     */
    private final JsonObjectBuilder kexBuilder = Json.createObjectBuilder();

    /**
     * This is the mapping object that stores the signature algorithm data. It
     * leverages the fact that the JsonObject is a map where the order is
     * guaranteed.
     */
    private final JsonObjectBuilder sigsBuilder = Json.createObjectBuilder();

    /**
     * JCA name.
     */
    public static final String N = "n";

    /**
     * Key length in bits.
     */
    public static final String K = "k";

    /**
     * IV length bits.
     */
    public static final String I = "i";

    /**
     * Key Type.
     */
    public static final String T = "t";

    /**
     * Adds to the jwaToJca map if the algorithm is available for the bit length
     * specified
     * 
     * @param jwa
     * @param jca
     * @param crv
     *            curve name
     */
    private void putEcIfAvailable(String jwa,
            String jca,
            String crv) {

        try {
            Signature.getInstance(jca);
            NamedEllipticCurve.valueOf(crv);
            JsonObjectBuilder sigBuilder = Json.createObjectBuilder();
            sigBuilder.add(N, jca);
            sigBuilder.add(T, KeyType.EC.name());
            sigsBuilder.add(jwa, sigBuilder);
        } catch (GeneralSecurityException e) {
            System.out.println(jwa + " is not supported");
        }
    }

    /**
     * Adds to the jwaToJca map if the algorithm is available for the bit length
     * specified
     * 
     * @param jwa
     * @param jca
     * @param crv
     *            curve name
     */
    private void putRsaIfAvailable(String jwa,
            String jca) {

        try {
            Signature.getInstance(jca);
            JsonObjectBuilder sigBuilder = Json.createObjectBuilder();
            sigBuilder.add(N, jca);
            sigBuilder.add(T, KeyType.RSA.name());
            sigsBuilder.add(jwa, sigBuilder);
        } catch (GeneralSecurityException e) {
            System.out.println(jwa + " is not supported");
        }
    }

    /**
     * Adds to the jwaToJca map if the algorithm is available for the bit length
     * specified
     * 
     * @param jwa
     * @param jca
     */
    private void putIfAvailable(String jwa,
            String jca,
            int keySize,
            int ivLen) {

        try {
            KeyGenerator gen = KeyGenerator.getInstance("AES");
            gen.init(keySize);
            Cipher.getInstance(jca)
                    .init(Cipher.ENCRYPT_MODE, gen.generateKey());
            JsonObjectBuilder encBuilder = Json.createObjectBuilder();
            encBuilder.add(N, jca);
            encBuilder.add(K, keySize);
            encBuilder.add(I, ivLen);
            encsBuilder.add(jwa, encBuilder);
        } catch (GeneralSecurityException e) {
            System.out.println(jwa + " is not supported");
        }
    }

    public JcaJsonWebAlgorithm() {
        
        /**
         * Advanced Encryption Standard (AES) using 256 bit keys in Galois/Counter
         * Mode. Note this is only available from JDK8 onwards or Bouncy Castle.
         */
        putIfAvailable("A256GCM", "AES/GCM/NoPadding", 256,96);

        /**
         * Advanced Encryption Standard (AES) using 256 bit keys in Cipher Block
         * Chaining mode.
         */
        putIfAvailable("A256CBC", "AES/CBC/PKCS5Padding", 256,16);

        /**
         * Advanced Encryption Standard (AES) using 128 bit keys in Galois/Counter
         * Mode.
         */
        putIfAvailable("A128GCM", "AES/GCM/NoPadding", 128, 96);

        /**
         * Advanced Encryption Standard (AES) using 128 bit keys in Cipher Block
         * Chaining mode.
         */
        putIfAvailable("A128CBC", "AES/CBC/PKCS5Padding", 128,16);

        /**
         * ECDSA using P-521 curve and SHA-512 hash algorithm.
         */
        putEcIfAvailable("ES512", "SHA512withECDSA", "P521");

        /**
         * ECDSA using P-384 curve and SHA-384 hash algorithm.
         */
        putEcIfAvailable("ES384", "SHA384withECDSA", "P384");

        /**
         * ECDSA using P-256 curve and SHA-256 hash algorithm.
         */
        putEcIfAvailable("ES256", "SHA256withECDSA", "P256");

        /**
         * RSA using SHA-512 hash algorithm.
         */
        putRsaIfAvailable("RS512", "SHA512withRSA");
        /**
         * RSA using SHA-384 hash algorithm.
         */
        putRsaIfAvailable("RS384", "SHA384withRSA");
        /**
         * RSA using SHA-256 hash algorithm.
         */
        putRsaIfAvailable("RS256", "SHA256withRSA");

        /**
         * HMAC using SHA-256 hash algorithm.
         */
        //HS256("HmacSHA256", 256),
        /**
         * HMAC using SHA-384 hash algorithm.
         */
        //HS384("HmacSHA384", 384),
        /**
         * HMAC using SHA-512 hash algorithm.
         */
        //HS512("HmacSHA512", 512),

        /**
         * RSA using Optimal Asymmetric Encryption Padding (OAEP).
         */
        //@XmlEnumValue("RSA-OAEP")
        //RSA_OAEP("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", 0),
        /**
         * RSA using RSA-PKCS1-1.5 padding.
         */
        //RSA1_5("RSA/ECB/PKCS1Padding", 0);
        
    }
}
