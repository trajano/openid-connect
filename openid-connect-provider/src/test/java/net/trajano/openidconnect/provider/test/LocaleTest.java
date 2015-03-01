package net.trajano.openidconnect.provider.test;

import java.util.Locale;

import org.junit.Assert;
import org.junit.Test;

public class LocaleTest {

    @Test
    public void testLocaleWithDashes() {

        Locale enDashCA = Locale.forLanguageTag("en-CA");
        Assert.assertEquals("CA", enDashCA.getCountry());
        Assert.assertEquals("en", enDashCA.getLanguage());
    }
}
