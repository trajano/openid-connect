package net.trajano.openidconnect.crypto.test;

import net.trajano.openidconnect.token.IdToken;

import org.junit.Assert;
import org.junit.Test;

public class IdTokenTest {

    @Test
    public void testCreate() {

        IdToken token = new IdToken();
        token.resetIssueAndExpiration(3600);
        Assert.assertEquals(3600, token.getExp() - token.getIat());
    }
}
