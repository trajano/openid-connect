package net.trajano.openidconnect.crypto.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.InputStream;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.trajano.openidconnect.auth.JoseHeader;
import net.trajano.openidconnect.auth.JsonWebToken;
import net.trajano.openidconnect.crypto.Base64Url;
import net.trajano.openidconnect.crypto.JWE;
import net.trajano.openidconnect.crypto.JsonWebAlgorithm;
import net.trajano.openidconnect.crypto.JsonWebKey;
import net.trajano.openidconnect.rs.JsonWebKeyProvider;

import org.junit.Before;
import org.junit.Test;

public class JweTest {

    private byte[] aad;

    private byte[] cek;

    final String decoded = "The true sign of intelligence is not knowledge but imagination.";

    private byte[] iv;

    private String joseHeader = "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}";

    final String jwe = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ."
    // encrypted key
            + "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg."

            // initialization vector (aka salt)
            + "48V1_ALb6US04U3b."

            // ciphertext
            + "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A."

            // Authentication tag (a 128-bits of data added at the end)
            + "XFBoMYUZodetZdvTiFvSkQ";

    private JsonWebKey privateJwk;

    private JsonWebKey publicJwk;

    @Before
    public void setKeys() throws Exception {

        final int[] cekInt = new int[] { 177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252 };
        cek = new byte[cekInt.length];
        for (int i = 0; i < cekInt.length; ++i) {
            cek[i] = (byte) cekInt[i];
        }

        final int[] ivInt = new int[] { 227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219 };
        iv = new byte[ivInt.length];
        for (int i = 0; i < ivInt.length; ++i) {
            iv[i] = (byte) ivInt[i];
        }

        final int[] aadInt = new int[] { 101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69, 116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73, 54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81 };
        aad = new byte[aadInt.length];
        for (int i = 0; i < aadInt.length; ++i) {
            aad[i] = (byte) aadInt[i];
        }
        {
            final InputStream is = Thread.currentThread()
                    .getContextClassLoader()
                    .getResourceAsStream("appendix.A.1.3.jwk");
            final JsonWebKeyProvider jsonWebKeyProvider = new JsonWebKeyProvider();
            jsonWebKeyProvider.isReadable(JsonWebKey.class, null, null, null);
            privateJwk = jsonWebKeyProvider.readFrom(JsonWebKey.class, null, null, null, null, is);
            is.close();
        }
        {
            final InputStream is = Thread.currentThread()
                    .getContextClassLoader()
                    .getResourceAsStream("appendix.A.1.3.pub");
            final JsonWebKeyProvider jsonWebKeyProvider = new JsonWebKeyProvider();
            jsonWebKeyProvider.isReadable(JsonWebKey.class, null, null, null);
            publicJwk = jsonWebKeyProvider.readFrom(JsonWebKey.class, null, null, null, null, is);
            is.close();
        }
    }

    @Test
    public void testBuildJoseHeader() throws Exception {

        final JoseHeader header = new JoseHeader();
        header.setAlg(JsonWebAlgorithm.RSA_OAEP);
        header.setEnc(JsonWebAlgorithm.A256GCM);
        assertEquals(joseHeader, header.toString());
    }

    @Test
    public void testCekEncryptDecrypt() throws Exception {

        final byte[] encryptedCek;
        {
            final Cipher cipher = Cipher.getInstance(JsonWebAlgorithm.RSA_OAEP.toJca());
            cipher.init(Cipher.ENCRYPT_MODE, publicJwk.toJcaKey());
            encryptedCek = cipher.doFinal(cek);
        }
        {
            final Cipher cipher = Cipher.getInstance(JsonWebAlgorithm.RSA_OAEP.toJca());
            cipher.init(Cipher.DECRYPT_MODE, privateJwk.toJcaKey());
            assertArrayEquals(cek, cipher.doFinal(encryptedCek));
        }
    }

    @Test
    public void testCekEncryptDecryptWithProvidedKey() throws Exception {

        final byte[] encryptedCek = Base64Url.decode("OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg");
        {
            final Cipher cipher = Cipher.getInstance(JsonWebAlgorithm.RSA_OAEP.toJca());
            cipher.init(Cipher.DECRYPT_MODE, privateJwk.toJcaKey());
            assertArrayEquals(cek, cipher.doFinal(encryptedCek));
        }
    }

    @Test
    public void testDecryptJweExampleFromSpec() throws Exception {

        assertEquals(decoded, new String(JWE.decrypt(jwe, privateJwk)));
    }

    @Test
    public void testEncryptDecryptJweExampleFromSpec() throws Exception {

        final String jwe = JWE.encrypt(decoded.getBytes(), publicJwk, JsonWebAlgorithm.RSA_OAEP, JsonWebAlgorithm.A256GCM);
        assertEquals(decoded, new String(JWE.decrypt(jwe, privateJwk)));
    }

    @Test
    public void testJoseHeader() throws Exception {

        final JsonWebToken jwt = new JsonWebToken(jwe);
        final JoseHeader joseHeader = jwt.getJoseHeader();
        assertEquals(JsonWebAlgorithm.RSA_OAEP, joseHeader.getAlg());
        assertEquals(JsonWebAlgorithm.A256GCM, joseHeader.getEnc());
    }

    @Test
    public void testRandomExample() throws Exception {

        final String text = "Live long and prosper.";

        final String jwe = JWE.encrypt(text.getBytes(), publicJwk, JsonWebAlgorithm.RSA_OAEP, JsonWebAlgorithm.A256GCM);
        assertEquals(text, new String(JWE.decrypt(jwe, privateJwk)));
    }

    @Test
    public void testReallyLongExample() throws Exception {

        Random r = new Random();
        byte[] plaintext = new byte[204080];
        r.nextBytes(plaintext);

        final String jwe = JWE.encrypt(plaintext, publicJwk, JsonWebAlgorithm.RSA_OAEP, JsonWebAlgorithm.A256GCM);
        assertArrayEquals(plaintext, JWE.decrypt(jwe, privateJwk));
    }

    @Test
    public void testJweExampleFromSpecJweAssembly() throws Exception {

        final String decoded = "The true sign of intelligence is not knowledge but imagination.";

        final Cipher cekCipher = Cipher.getInstance(JsonWebAlgorithm.RSA_OAEP.toJca());
        cekCipher.init(Cipher.ENCRYPT_MODE, publicJwk.toJcaKey());
        cekCipher.doFinal(cek);

        final GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        final Cipher contentCipher = Cipher.getInstance("AES/GCM/NoPadding");
        contentCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), spec);
        contentCipher.updateAAD(aad);
        final byte[] cipherTextAndAuthenticationTag = contentCipher.doFinal(decoded.getBytes());
        final String cipherText = Base64Url.encode(cipherTextAndAuthenticationTag, 0, cipherTextAndAuthenticationTag.length - 128 / 8);
        final String authenticationTag = Base64Url.encode(cipherTextAndAuthenticationTag, cipherTextAndAuthenticationTag.length - 128 / 8, 128 / 8);

        assertEquals("5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A", cipherText);
        assertEquals("XFBoMYUZodetZdvTiFvSkQ", authenticationTag);
    }

    @Test
    public void testKeyEncodings() {

        assertEquals("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ", Base64Url.encode(joseHeader));
        assertEquals("48V1_ALb6US04U3b", Base64Url.encode(iv));

    }

    @Test
    public void testRsaPrivateKey() throws Exception {

        final InputStream is = Thread.currentThread()
                .getContextClassLoader()
                .getResourceAsStream("appendix.A.1.3.jwk");
        final JsonWebKeyProvider jsonWebKeyProvider = new JsonWebKeyProvider();
        jsonWebKeyProvider.isReadable(JsonWebKey.class, null, null, null);
        final JsonWebKey jwk = jsonWebKeyProvider.readFrom(JsonWebKey.class, null, null, null, null, is);
        is.close();
        final RSAPrivateKey privateKey = (RSAPrivateKey) jwk.toJcaKey();
        assertNotNull(privateKey);
    }

    @Test
    public void testRsaPublicKey() throws Exception {

        final InputStream is = Thread.currentThread()
                .getContextClassLoader()
                .getResourceAsStream("appendix.A.1.3.pub");
        final JsonWebKeyProvider jsonWebKeyProvider = new JsonWebKeyProvider();
        jsonWebKeyProvider.isReadable(JsonWebKey.class, null, null, null);
        final JsonWebKey jwk = jsonWebKeyProvider.readFrom(JsonWebKey.class, null, null, null, null, is);
        is.close();
        final RSAPublicKey publicKey = (RSAPublicKey) jwk.toJcaKey();
        assertNotNull(publicKey);
    }

}
