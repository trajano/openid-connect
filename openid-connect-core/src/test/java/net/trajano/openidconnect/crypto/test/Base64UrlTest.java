package net.trajano.openidconnect.crypto.test;

import java.math.BigInteger;

import net.trajano.openidconnect.crypto.Base64Url;

import org.junit.Assert;
import org.junit.Test;

public class Base64UrlTest {

    /**
     * Tests the zero value as per <a href=
     * "http://self-issued.info/docs/draft-ietf-jose-json-web-algorithms-35.html#Terminology"
     * >Base64urlUInt terminology</a>.
     */
    @Test
    public void testZeroDecode() {

        Assert.assertEquals(BigInteger.ZERO, Base64Url.decodeUint("AA"));

    }

    @Test
    public void testZeroEncode() {

        Assert.assertEquals("AA", Base64Url.encodeUint(BigInteger.ZERO));
    }

    /**
     * <p>
     * Based on <a href=
     * "http://self-issued.info/docs/draft-ietf-jose-json-web-algorithms-35.html#eRSADef"
     * >definiton of e</a>.
     * </p>
     * <blockquote> For instance, when representing the value 65537, the octet
     * sequence to be base64url encoded MUST consist of the three octets [1, 0,
     * 1]; the resulting representation for this value is "AQAB". </blockquote>
     */
    @Test
    public void test65537() {

        Assert.assertEquals(65537, Base64Url.decodeUint("AQAB")
                .intValue());

        Assert.assertEquals("AQAB", Base64Url.encodeUint(new BigInteger("65537")));

    }
}
