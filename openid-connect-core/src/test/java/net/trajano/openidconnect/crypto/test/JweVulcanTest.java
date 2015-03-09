package net.trajano.openidconnect.crypto.test;

import static org.junit.Assert.assertEquals;

import java.io.InputStream;

import net.trajano.openidconnect.crypto.Base64Url;
import net.trajano.openidconnect.crypto.JsonWebKey;
import net.trajano.openidconnect.rs.JsonWebKeyProvider;

import org.junit.Before;
import org.junit.Test;

public class JweVulcanTest {

    private byte[] aad;

    private byte[] cek;

    final String decoded = "Live long and prosper.";

    private byte[] iv;

    private String joseHeader = "{\"alg\":\"RSA1_5\",\"enc\":\"A128CBC-HS256\"}";

    final String jwe = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."

    + "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm"

    + "1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc"

    + "HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF"

    + "NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8"

    + "rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv"

    + "-B3oWh2TbqmScqXMR4gp_A."

    + "AxY8DCtDaGlsbGljb3RoZQ."

    + "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY."

    + "9hH0vgRfYgPnAHOd8stkvw";

    private JsonWebKey privateJwk;

    @Before
    public void setKeys() throws Exception {

        final int[] cekInt = new int[] { 40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6, 75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143, 112, 56, 102 };
        cek = new byte[cekInt.length];
        for (int i = 0; i < cekInt.length; ++i) {
            cek[i] = (byte) cekInt[i];
        }

        final int[] ivInt = new int[] { 3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101 };
        iv = new byte[ivInt.length];
        for (int i = 0; i < ivInt.length; ++i) {
            iv[i] = (byte) ivInt[i];
        }

        aad = Base64Url.encode(joseHeader)
                .getBytes();

        {
            final InputStream is = Thread.currentThread()
                    .getContextClassLoader()
                    .getResourceAsStream("appendix.A.2.3.jwk");
            final JsonWebKeyProvider jsonWebKeyProvider = new JsonWebKeyProvider();
            jsonWebKeyProvider.isReadable(JsonWebKey.class, null, null, null);
            privateJwk = jsonWebKeyProvider.readFrom(JsonWebKey.class, null, null, null, null, is);
            is.close();
        }
    }

    @Test
    public void testDecryptJweExampleFromSpec() throws Exception {

        assertEquals(decoded, new String(JWE.decrypt(jwe, privateJwk)));
    }

    @Test
    public void testEncryptDecryptJweExampleFromSpec() throws Exception {

        final String jwe = JWE.encrypt(decoded.getBytes(), privateJwk, "RSA1_5", "A128CBC-HS256");
        System.out.println(jwe);
        assertEquals(decoded, new String(JWE.decrypt(jwe, privateJwk)));
    }
}
