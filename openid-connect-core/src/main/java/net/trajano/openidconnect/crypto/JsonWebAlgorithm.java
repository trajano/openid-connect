package net.trajano.openidconnect.crypto;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.ECParameterSpec;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

import net.trajano.openidconnect.internal.Log;

/**
 * <p>
 * This maps the algorithms to their JCA counterparts. This is a singleton to
 * prevent multiple instantiations that cost environment analysis time.
 * </p>
 * <p>
 * This mapping is based on Appendix A & B of <a href=
 * "http://self-issued.info/docs/draft-ietf-jose-json-web-algorithms-00.html">
 * JWA</a>.
 * </p>
 *
 * @author Archimedes
 */
public class JsonWebAlgorithm {

    public static final String A128CBC = "A128CBC";

    /**
     * Advanced Encryption Standard (AES) using 256 bit keys in Cipher Block
     * Chaining mode.
     */
    public static final String A256CBC = "A256CBC";

    /**
     * Advanced Encryption Standard (AES) using 256 bit keys in Galois/Counter
     * Mode.
     */
    public static final String A256GCM = "A256GCM";

    /**
     * Instance.
     */
    private static JsonWebAlgorithm INSTANCE = new JsonWebAlgorithm();

    public static final String RS256 = "RS256";

    /**
     * RSA using Optimal Asymmetric Encryption Padding (OAEP).
     */
    public static final String RSA_OAEP = "RSA-OAEP";

    public static final String RSA1_5 = "RSA1_5";

    public static String[] getEncAlgorithms() {

        return INSTANCE.encs.toArray(new String[0]);
    }

    public static String getFirstMatchingEncAlgorithm(final List<String> encryptionEncValuesSupported) {

        for (final String enc : INSTANCE.encs) {
            if (encryptionEncValuesSupported.contains(enc)) {
                return enc;
            }
        }
        return null;
    }

    public static String getFirstMatchingKexAlgorithm(final List<String> encryptionAlgValuesSupported) {

        for (final String kex : INSTANCE.kexs) {
            if (encryptionAlgValuesSupported.contains(kex)) {
                return kex;
            }
        }
        return null;
    }

    public static int getIvLen(final String enc) {

        return INSTANCE.jwaIvLenMap.get(enc);
    }

    public static String[] getKexAlgorithms() {

        return INSTANCE.kexs.toArray(new String[0]);
    }

    public static int getKeySize(final String enc) throws GeneralSecurityException {

        if (INSTANCE.jwaKeySizeMap.containsKey(enc)) {
            return INSTANCE.jwaKeySizeMap.get(enc);
        } else {
            throw new GeneralSecurityException(
                "enc algorithm " + enc + " does not have a defined keysize or is not supported.");
        }
    }

    public static String getMacAlg(final String enc) {

        return INSTANCE.jwaJcaMacMap.get(enc);
    }

    public static String[] getSigAlgorithms() {

        return INSTANCE.sigs.toArray(new String[0]);
    }

    public static boolean isGcm(final String enc) {

        return A256GCM.equals(enc) || "A128GCM".equals(enc);
    }

    public static boolean isMac(final String alg) {

        return INSTANCE.macs.contains(alg);
    }

    /**
     * Converts a JWA to the JCA equivalent name.
     *
     * @param jwa
     *            JSON Web algorithm name
     * @return Java Crypto Architecture algorithm name.
     * @throws NoSuchAlgorithmException
     *             algorithm not available
     */
    public static String toJca(final String jwa) throws NoSuchAlgorithmException {

        if (INSTANCE.jwaJcaMap.get(jwa) != null) {
            return INSTANCE.jwaJcaMap.get(jwa);
        } else {
            throw new NoSuchAlgorithmException("algorithm " + jwa + " is not supported");
        }
    }

    /**
     * Encryption algorithms list. The data is in order of preference with the
     * strongest being the first entry.
     */
    private final List<String> encs = new LinkedList<>();

    /**
     * A map of EC JWA names to EC Curves.
     */
    private final Map<String, ECParameterSpec> jwaEcMap = new HashMap<>();

    /**
     * A map of AES JWA names to initialVector sizes.
     */
    private final Map<String, Integer> jwaIvLenMap = new HashMap<>();

    /**
     * A map of AES JWA names to MAC algorithms if available.
     */
    private final Map<String, String> jwaJcaMacMap = new HashMap<>();

    /**
     * A map of JWA names to JCA names.
     */
    private final Map<String, String> jwaJcaMap = new HashMap<>();

    /**
     * A map of AES JWA names to key sizes.
     */
    private final Map<String, Integer> jwaKeySizeMap = new HashMap<>();

    /**
     * Key Exchange algorithms list. The data is in order of preference with the
     * strongest being the first entry.
     */
    private final List<String> kexs = new LinkedList<>();

    /**
     * Set of mac algorithms registered.
     */
    private final Set<String> macs = new HashSet<>();

    /**
     * Signature algorithms list. The data is in order of preference with the
     * strongest being the first entry.
     */
    private final List<String> sigs = new LinkedList<>();

    private JsonWebAlgorithm() {

        /**
         * Advanced Encryption Standard (AES) using 256 bit keys in
         * Galois/Counter Mode. Note this is only available from JDK8 onwards or
         * Bouncy Castle.
         */
        putEncIfAvailable(A256GCM, "AES/GCM/NoPadding", null, 256, 96);

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

        putMacIfAvailable("HS512", "HmacSHA512");
        putMacIfAvailable("HS384", "HmacSHA384");
        putMacIfAvailable("HS256", "HmacSHA256");

        /**
         * RSA using Optimal Asymmetric Encryption Padding (OAEP).
         */
        putKexIfAvailable(RSA_OAEP, "RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        /**
         * RSA using RSA-PKCS1-1.5 padding.
         */
        putKexIfAvailable("RSA1_5", "RSA/ECB/PKCS1Padding");

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
    private void putEcIfAvailable(final String jwa,
        final String jca,
        final NamedEllipticCurve crv) {

        try {
            Signature.getInstance(jca);
            jwaJcaMap.put(jwa, jca);
            jwaEcMap.put(jwa, crv.toECParameterSpec());
            sigs.add(jwa);
        } catch (final GeneralSecurityException e) {
            Log.fine("algNotSupportedForSig", jwa);
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
    private void putEncIfAvailable(final String jwa,
        final String jca,
        final String jcaMac,
        final int keySize,
        final int ivLen) {

        try {
            final KeyGenerator gen = KeyGenerator.getInstance("AES");
            gen.init(keySize);
            Cipher.getInstance(jca).init(Cipher.ENCRYPT_MODE, gen.generateKey());
            if (jcaMac != null) {
                Mac.getInstance(jcaMac);
                jwaJcaMacMap.put(jwa, jcaMac);
            }
            jwaJcaMap.put(jwa, jca);
            jwaKeySizeMap.put(jwa, keySize);
            jwaIvLenMap.put(jwa, ivLen);
            encs.add(jwa);
        } catch (final GeneralSecurityException e) {
            Log.fine("algNotSupportedForEnc", jwa);
        }
    }

    /**
     * Adds to the jwaToJca map if the algorithm is available for the bit length
     * specified
     *
     * @param jwa
     * @param jca
     */
    private void putKexIfAvailable(final String jwa,
        final String jca) {

        try {
            Cipher.getInstance(jca);
            jwaJcaMap.put(jwa, jca);
            kexs.add(jwa);
        } catch (final GeneralSecurityException e) {
            Log.fine("algNotSupportedForKex", jwa);
        }
    }

    /**
     * Adds to the jwaToJca map if the algorithm is available for the bit length
     * specified
     *
     * @param jwa
     * @param jca
     */
    private void putMacIfAvailable(final String jwa,
        final String jca) {

        try {
            Mac.getInstance(jca);
            jwaJcaMap.put(jwa, jca);
            sigs.add(jwa);
            macs.add(jwa);
        } catch (final GeneralSecurityException e) {
            Log.fine("algNotSupportedForSig", jwa);
        }
    }

    /**
     * Adds to the jwaToJca map if the algorithm is available for the bit length
     * specified
     *
     * @param jwa
     * @param jca
     */
    private void putRsaIfAvailable(final String jwa,
        final String jca) {

        try {
            Signature.getInstance(jca);
            jwaJcaMap.put(jwa, jca);
            sigs.add(jwa);
        } catch (final GeneralSecurityException e) {
            Log.fine("algNotSupportedForSig", jwa);
        }
    }

}
