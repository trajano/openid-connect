package net.trajano.openidconnect.crypto;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.spec.ECParameterSpec;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

import net.trajano.openidconnect.internal.Log;

/**
 * <p>
 * This maps the algorithms to their JCA counterparts. This is a singleton to
 * prevent multiple instantiations that cost environment analysis time.
 * </p>
 * See Appendix A & B of
 * http://self-issued.info/docs/draft-ietf-jose-json-web-algorithms-00.html.
 * 
 * @author Archimedes
 */
public class JsonWebAlgorithm {

    /**
     * Logger
     */
    public static Log LOG = Log.getInstance();

    /**
     * Instance.
     */
    private static JsonWebAlgorithm INSTANCE = new JsonWebAlgorithm();

    /**
     * Encryption algorithms list. The data is in order of preference with the
     * strongest being the first entry.
     */
    private final List<String> encs = new LinkedList<>();

    /**
     * Key Exchange algorithms list. The data is in order of preference with the
     * strongest being the first entry.
     */
    private final List<String> kexs = new LinkedList<>();

    /**
     * Signature algorithms list. The data is in order of preference with the
     * strongest being the first entry.
     */
    private final List<String> sigs = new LinkedList<>();

    /**
     * A map of JWA names to JCA names.
     */
    private final Map<String, String> jwaJcaMap = new HashMap<>();

    /**
     * A map of EC JWA names to EC Curves.
     */
    private final Map<String, ECParameterSpec> jwaEcMap = new HashMap<>();

    /**
     * A map of AES JWA names to key sizes.
     */
    private final Map<String, Integer> jwaKeySizeMap = new HashMap<>();

    /**
     * A map of AES JWA names to initialVector sizes.
     */
    private final Map<String, Integer> jwaIvLenMap = new HashMap<>();

    /**
     * A map of AES JWA names to MAC algorithms if available.
     */
    private Map<String, String> jwaJcaMacMap = new HashMap<>();

    /**
     * RSA using Optimal Asymmetric Encryption Padding (OAEP).
     */
    public static final String RSA_OAEP = "RSA-OAEP";

    /**
     * Advanced Encryption Standard (AES) using 256 bit keys in Cipher Block
     * Chaining mode.
     */
    public static final String A256CBC = "A256CBC";

    public static final String A256GCM = "A256GCM";

    public static final String RSA1_5 = "RSA1_5";

    public static final String RS256 = "RS256";

    public static final String A128CBC = "A128CBC";

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
            NamedEllipticCurve crv) {

        try {
            Signature.getInstance(jca);
            jwaJcaMap.put(jwa, jca);
            jwaEcMap.put(jwa, crv.toECParameterSpec());
            sigs.add(jwa);
        } catch (GeneralSecurityException e) {
            LOG.fine("algNotSupportedForSig", new Object[] { jwa });
        }
    }

    /**
     * Adds to the jwaToJca map if the algorithm is available for the bit length
     * specified
     * 
     * @param jwa
     * @param jca
     */
    private void putRsaIfAvailable(String jwa,
            String jca) {

        try {
            Signature.getInstance(jca);
            jwaJcaMap.put(jwa, jca);
            sigs.add(jwa);
        } catch (GeneralSecurityException e) {
            LOG.fine("algNotSupportedForSig", new Object[] { jwa });
        }
    }

    /**
     * Adds to the jwaToJca map if the algorithm is available for the bit length
     * specified
     * 
     * @param jwa
     * @param jca
     */
    private void putKexIfAvailable(String jwa,
            String jca) {

        try {
            Cipher.getInstance(jca);
            jwaJcaMap.put(jwa, jca);
            kexs.add(jwa);
        } catch (GeneralSecurityException e) {
            LOG.fine("algNotSupportedForKex", new Object[] { jwa });
        }
    }

    /**
     * Adds to the jwaToJca map if the algorithm is available for the bit length
     * specified
     * 
     * @param jwa
     * @param jca
     * @param jcaMac
     *            JCA Mac algorithm, may be null.
     */
    private void putEncIfAvailable(String jwa,
            String jca,
            String jcaMac,
            int keySize,
            int ivLen) {

        try {
            KeyGenerator gen = KeyGenerator.getInstance("AES");
            gen.init(keySize);
            Cipher.getInstance(jca)
                    .init(Cipher.ENCRYPT_MODE, gen.generateKey());
            if (jcaMac != null) {
                Mac.getInstance(jcaMac);
                jwaJcaMacMap.put(jwa, jcaMac);
            }
            jwaJcaMap.put(jwa, jca);
            jwaKeySizeMap.put(jwa, keySize);
            jwaIvLenMap.put(jwa, ivLen);
            encs.add(jwa);
        } catch (GeneralSecurityException e) {
            LOG.fine("algNotSupportedForEnc", new Object[] { jwa });
        }
    }

    private JsonWebAlgorithm() {

        /**
         * Advanced Encryption Standard (AES) using 256 bit keys in
         * Galois/Counter Mode. Note this is only available from JDK8 onwards or
         * Bouncy Castle.
         */
        putEncIfAvailable("A256GCM", "AES/GCM/NoPadding", null, 256, 96);

        /**
         * Advanced Encryption Standard (AES) using 256 bit keys in Cipher Block
         * Chaining mode. With HMAC using SHA-512 hash algorithm.
         */
        putEncIfAvailable("A256CBC-HS512", "AES/CBC/PKCS5Padding", "HmacSHA512", 256, 16);

        /**
         * Advanced Encryption Standard (AES) using 256 bit keys in Cipher Block
         * Chaining mode. With HMAC using SHA-384 hash algorithm.
         */
        putEncIfAvailable("A256CBC-HS384", "AES/CBC/PKCS5Padding", "HmacSHA384", 256, 16);

        /**
         * Advanced Encryption Standard (AES) using 256 bit keys in Cipher Block
         * Chaining mode. With HMAC using SHA-256 hash algorithm.
         */
        putEncIfAvailable("A256CBC-HS256", "AES/CBC/PKCS5Padding", "HmacSHA256", 256, 16);

        /**
         * Advanced Encryption Standard (AES) using 256 bit keys in Cipher Block
         * Chaining mode.
         */
        putEncIfAvailable(A256CBC, "AES/CBC/PKCS5Padding", null, 256, 16);

        /**
         * Advanced Encryption Standard (AES) using 128 bit keys in
         * Galois/Counter Mode.
         */
        putEncIfAvailable("A128GCM", "AES/GCM/NoPadding", null, 128, 96);

        /**
         * Advanced Encryption Standard (AES) using 256 bit keys in Cipher Block
         * Chaining mode. With HMAC using SHA-512 hash algorithm.
         */
        putEncIfAvailable("A128CBC-HS512", "AES/CBC/PKCS5Padding", "HmacSHA512", 128, 16);

        /**
         * Advanced Encryption Standard (AES) using 256 bit keys in Cipher Block
         * Chaining mode. With HMAC using SHA-384 hash algorithm.
         */
        putEncIfAvailable("A128CBC-HS384", "AES/CBC/PKCS5Padding", "HmacSHA384", 128, 16);

        /**
         * Advanced Encryption Standard (AES) using 256 bit keys in Cipher Block
         * Chaining mode. With HMAC using SHA-256 hash algorithm.
         */
        putEncIfAvailable("A128CBC-HS256", "AES/CBC/PKCS5Padding", "HmacSHA256", 128, 16);

        /**
         * Advanced Encryption Standard (AES) using 128 bit keys in Cipher Block
         * Chaining mode.
         */
        putEncIfAvailable("A128CBC", "AES/CBC/PKCS5Padding", null, 128, 16);

        /**
         * ECDSA using P-521 curve and SHA-512 hash algorithm.
         */
        putEcIfAvailable("ES512", "SHA512withECDSA", NamedEllipticCurve.P521);

        /**
         * ECDSA using P-384 curve and SHA-384 hash algorithm.
         */
        putEcIfAvailable("ES384", "SHA384withECDSA", NamedEllipticCurve.P384);

        /**
         * ECDSA using P-256 curve and SHA-256 hash algorithm.
         */
        putEcIfAvailable("ES256", "SHA256withECDSA", NamedEllipticCurve.P256);

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
         * RSA using Optimal Asymmetric Encryption Padding (OAEP).
         */
        putKexIfAvailable(RSA_OAEP, "RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        /**
         * RSA using RSA-PKCS1-1.5 padding.
         */
        putKexIfAvailable("RSA1_5", "RSA/ECB/PKCS1Padding");

    }

    public static String toJca(String jwa) {

        return INSTANCE.jwaJcaMap.get(jwa);
    }

    public static int getIvLen(String enc) {

        return INSTANCE.jwaIvLenMap.get(enc);
    }

    public static String getMacAlg(String enc) {

        return INSTANCE.jwaJcaMacMap.get(enc);
    }

    public static int getKeySize(String enc) {

        return INSTANCE.jwaKeySizeMap.get(enc);
    }

    public static boolean isGcm(String enc) {

        return "A256GCM".equals(enc) || "A128GCM".equals(enc);
    }

}
