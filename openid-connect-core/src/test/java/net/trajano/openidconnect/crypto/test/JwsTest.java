package net.trajano.openidconnect.crypto.test;

import java.util.Random;

import net.trajano.openidconnect.crypto.Base64Url;
import net.trajano.openidconnect.crypto.JsonWebKey;
import net.trajano.openidconnect.crypto.JsonWebToken;
import net.trajano.openidconnect.crypto.JsonWebTokenBuilder;
import net.trajano.openidconnect.crypto.JsonWebTokenProcessor;
import net.trajano.openidconnect.crypto.OctWebKey;

import org.junit.Assert;
import org.junit.Test;

public class JwsTest {

    @Test
    public void testWithHS256FromSpec() throws Exception {

        final JsonWebKey jwk = new OctWebKey(Base64Url.decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"));

        byte[] payload = new byte[] { 123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125 };
        String jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        JsonWebTokenProcessor p = new JsonWebTokenProcessor(jws).allowJwkToBeSet(true)
                .jwk(jwk);
        Assert.assertArrayEquals(payload, p.getPayload());
    }

    @Test
    public void testWithHS256() throws Exception {

        Random r = new Random();

        byte[] macKey = new byte[128];
        final JsonWebKey jwk = new OctWebKey(macKey);

        byte[] payload = new byte[60000];
        r.nextBytes(payload);

        JsonWebTokenBuilder b = new JsonWebTokenBuilder();
        b.payload(payload);
        b.alg("HS256");
        b.jwk(jwk);
        b.compress(true);
        JsonWebToken jws = b.build();

        JsonWebTokenProcessor p = new JsonWebTokenProcessor(jws).allowJwkToBeSet(true)
                .jwk(jwk);
        Assert.assertArrayEquals(payload, p.getPayload());
    }
}
