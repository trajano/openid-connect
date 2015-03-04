package net.trajano.openidconnect.provider.test;

import java.net.URI;

import net.trajano.openidconnect.internal.FormPostBuilder;

import org.junit.Test;

public class FormPostBuilderTest {

    @Test
    public void testFormPostBuilder() {

        FormPostBuilder b = new FormPostBuilder(URI.create("https://i.trajano.net/cb"));
        b.put("state", "asdfasdfasdf");
        System.out.println(b.buildFormPost());
    }
}
