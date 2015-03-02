package net.trajano.openidconnect.provider.test;

import java.nio.charset.Charset;
import java.util.Locale;

import org.junit.Assert;
import org.junit.Test;

public class JreTest {

    @Test
    public void testCharsets() {

        System.out.println(Charset.availableCharsets());
    }

    @Test
    public void testLocaleWithDashes() {

        final Locale enDashCA = Locale.forLanguageTag("en-CA");
        Assert.assertEquals("CA", enDashCA.getCountry());
        Assert.assertEquals("en", enDashCA.getLanguage());
    }
}
