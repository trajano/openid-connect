package net.trajano.openidconnect.jaspic.test;

import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.trajano.openidconnect.core.OpenIdConnectKey;
import net.trajano.openidconnect.jaspic.OpenIdConnectAuthModule;

import org.junit.Test;
import org.mockito.ArgumentCaptor;

import com.google.common.collect.ImmutableMap;

public class AuthSequenceIT {

    @Test
    public void testRedirectToEndpoint() throws Exception {

        final OpenIdConnectAuthModule module = new OpenIdConnectAuthModule();

        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);
        final Map<String, String> options = ImmutableMap.<String, String> builder()
                .put(OpenIdConnectAuthModule.ISSUER_URI_KEY, "https://accounts.google.com")
                .put(OpenIdConnectAuthModule.REDIRECTION_ENDPOINT_URI_KEY, "/app/oauth2")
                .put(OpenIdConnectKey.CLIENT_ID, "clientID")
                .put(OpenIdConnectKey.CLIENT_SECRET, "clientSecret")
                .build();
        module.initialize(mockRequestPolicy, null, null, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.getRequestURL()).thenReturn(new StringBuffer("https://i.trajano.net:8443/util/ejb2"));
        when(servletRequest.getRequestURI()).thenReturn("/util/ejb2");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getLocales()).thenReturn(Collections.enumeration(Arrays.asList(Locale.CANADA)));
        when(servletRequest.isSecure()).thenReturn(true);

        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final Subject client = new Subject();
        assertEquals(AuthStatus.SEND_CONTINUE, module.validateRequest(messageInfo, client, null));
        ArgumentCaptor<String> uriCaptor = ArgumentCaptor.forClass(String.class);
        verify(servletResponse).sendRedirect(uriCaptor.capture());
        assertThat(uriCaptor.getValue(), startsWith("https://accounts.google.com/o/oauth2/auth"));
    }

    @Test
    public void testRedirectToEndpointWithQueryString() throws Exception {

        final OpenIdConnectAuthModule module = new OpenIdConnectAuthModule();

        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);
        final Map<String, String> options = ImmutableMap.<String, String> builder()
                .put(OpenIdConnectAuthModule.ISSUER_URI_KEY, "https://accounts.google.com")
                .put(OpenIdConnectAuthModule.REDIRECTION_ENDPOINT_URI_KEY, "/app/oauth2")
                .put(OpenIdConnectKey.CLIENT_ID, "clientID")
                .put(OpenIdConnectKey.CLIENT_SECRET, "clientSecret")
                .build();
        module.initialize(mockRequestPolicy, null, null, options);

        final MessageInfo messageInfo = mock(MessageInfo.class);

        final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        when(servletRequest.getMethod()).thenReturn("GET");
        when(servletRequest.getRequestURL()).thenReturn(new StringBuffer("https://i.trajano.net:8443/util/ejb2"));
        when(servletRequest.getRequestURI()).thenReturn("/util/ejb2");
        when(servletRequest.getContextPath()).thenReturn("/util");
        when(servletRequest.getQueryString()).thenReturn("q=foo");
        when(servletRequest.getLocales()).thenReturn(Collections.enumeration(Arrays.asList(Locale.CANADA)));
        when(servletRequest.isSecure()).thenReturn(true);

        when(messageInfo.getRequestMessage()).thenReturn(servletRequest);

        final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
        when(messageInfo.getResponseMessage()).thenReturn(servletResponse);

        final Subject client = new Subject();
        assertEquals(AuthStatus.SEND_CONTINUE, module.validateRequest(messageInfo, client, null));
        ArgumentCaptor<String> uriCaptor = ArgumentCaptor.forClass(String.class);
        verify(servletResponse).sendRedirect(uriCaptor.capture());
        assertThat(uriCaptor.getValue(), startsWith("https://accounts.google.com/o/oauth2/auth"));
    }
}
