package net.trajano.openidconnect.crypto.test;

import static org.junit.Assert.assertEquals;

import java.security.MessageDigest;
import java.util.UUID;

import net.trajano.openidconnect.crypto.Encoding;

import org.junit.Test;

public class AtHashTest {

    @Test
    public void testHash() throws Exception {

        final String atHash = "-EsTxDmUFRxSI0H_ZpbHiw";

        final String accessToken = "ya29.OwHWAP05yaZvR92b67pAxfX5xHH5KNxA1mhh-zInoQ5vhK-Vuib1-Hqj";

        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        final byte[] digestedBytes = digest.digest(accessToken.getBytes());

        assertEquals(atHash, Encoding.base64urlEncode(digestedBytes, 0, 128 / 8));

    }

    @Test
    public void testHashGenerated() throws Exception {

        final String accessToken = UUID.randomUUID()
                .toString();

        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        final byte[] digestedBytes = digest.digest(accessToken.getBytes());

        Encoding.base64urlEncode(digestedBytes, 0, 128 / 8);

    }
}
