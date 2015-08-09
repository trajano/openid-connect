package net.trajano.openidconnect.jaspic.test;

import static net.trajano.openidconnect.crypto.Encoding.base64urlDecode;
import static net.trajano.openidconnect.crypto.Encoding.base64urlEncode;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Matchers;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import com.google.common.base.Predicate;

import net.trajano.openidconnect.jaspic.OpenIdConnectAuthModule;
import net.trajano.openidconnect.jaspic.internal.CipherUtil;
import net.trajano.openidconnect.jaspic.internal.TokenCookie;

/**
 * Tests using Heroku.
 */
public class GoogleTest {

    private Cookie ageCookie;

    private WebDriver b;

    private String clientId;

    private String clientSecret;

    private String finalUrl;

    private SecretKey secretKey;

    private TokenCookie tokenCookie;

    private MessagePolicy mockRequestPolicy() {

        final MessagePolicy mockRequestPolicy = mock(MessagePolicy.class);
        when(mockRequestPolicy.isMandatory()).thenReturn(true);
        return mockRequestPolicy;
    }

    private HttpServletRequest mockRequestWithCurrentUrl() {

        return mockRequestWithUrl(b.getCurrentUrl());
    }

    private HttpServletRequest mockRequestWithUrl(final String urlString) {

        final HttpServletRequest req = mock(HttpServletRequest.class);
        final URI uri = URI.create(urlString);
        if (uri.getQuery() != null) {
            for (final String queryParam : uri.getQuery()
                .split("&")) {
                when(req.getParameter(queryParam.substring(0, queryParam.indexOf('=')))).thenReturn(queryParam.substring(queryParam.indexOf('=') + 1));
                when(req.getRequestURL()).thenReturn(new StringBuffer(urlString.substring(0, urlString.indexOf("?"))));
            }
        } else {
            when(req.getRequestURL()).thenReturn(new StringBuffer(urlString));
        }
        when(req.getContextPath()).thenReturn("/sample");
        when(req.isSecure()).thenReturn(true);
        when(req.getRemoteAddr()).thenReturn("8.8.8.8");
        when(req.getMethod()).thenReturn("GET");
        when(req.getRequestURI()).thenReturn(uri.getPath());
        return req;
    }

    private HttpServletResponse mockResponse() {

        final HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.encodeRedirectURL(Matchers.anyString())).then(new Answer<String>() {

            @Override
            public String answer(final InvocationOnMock invocation) throws Throwable {

                final Object[] args = invocation.getArguments();
                return (String) args[0];
            }
        });
        return resp;
    }

    private void redirectFromResponse(final HttpServletResponse resp) throws IOException {

        final ArgumentCaptor<String> redirectUrl = ArgumentCaptor.forClass(String.class);
        verify(resp).sendRedirect(redirectUrl.capture());
        b.get(redirectUrl.getValue());
        System.out.println(redirectUrl.getValue());

    }

    @Before
    public void setUpBrowser() throws Exception {

        b = new FirefoxDriver();

    }

    @After
    public void tearDownBrowser() {

        b.quit();
    }

    @Test
    public void testWithTheModule() throws Exception {

        clientId = System.getProperty("google.client_id");
        clientSecret = System.getProperty("google.client_secret");

        if (clientId == null || clientSecret == null) {
            // Don't bother with the test.
            return;
        }

        secretKey = CipherUtil.buildSecretKey(clientId, clientSecret);

        final Map<String, String> options;

        {
            final OpenIdConnectAuthModule module = new OpenIdConnectAuthModule();
            options = new HashMap<>();
            options.put("client_id", clientId);
            options.put("client_secret", clientSecret);
            options.put("issuer_uri", "https://accounts.google.com");
            options.put("scope", "openid");
            options.put(OpenIdConnectAuthModule.COOKIE_CONTEXT_KEY, "/");
            options.put(OpenIdConnectAuthModule.REDIRECTION_ENDPOINT_URI_KEY, "/sample/cb");

            final CallbackHandler handler = mock(CallbackHandler.class);
            module.initialize(mockRequestPolicy(), null, handler, options);

            final MessageInfo messageInfo = mock(MessageInfo.class);
            final HttpServletRequest req = mockRequestWithUrl("https://noriko.trajano.net:8181/sample/foo.jsp");
            when(messageInfo.getRequestMessage()).thenReturn(req);

            final HttpServletResponse resp = mock(HttpServletResponse.class);
            when(messageInfo.getResponseMessage()).thenReturn(resp);

            final Subject client = new Subject();
            assertEquals(AuthStatus.SEND_CONTINUE, module.validateRequest(messageInfo, client, null));
            redirectFromResponse(resp);
        }

        {
            b.findElement(By.id("Email")).click();
            b.findElement(By.id("Email")).sendKeys(System.getProperty("google.userid"));
            b.findElement(By.id("next")).click();

            final WebDriverWait wait = new WebDriverWait(b, 30);
            wait.until(ExpectedConditions.visibilityOfElementLocated(By.name("Passwd")));

            b.findElement(By.id("Passwd")).sendKeys(System.getProperty("google.password"));
            b.findElement(By.id("signIn")).click();

            // wait until Google finishes and redirects to another page.
            wait.until(new Predicate<WebDriver>() {

                @Override
                public boolean apply(final WebDriver input) {

                    return !b.getCurrentUrl().startsWith("https://accounts.google.com");
                }
            });

        }

        {
            final OpenIdConnectAuthModule module = new OpenIdConnectAuthModule();

            final CallbackHandler handler = mock(CallbackHandler.class);
            module.initialize(mockRequestPolicy(), null, handler, options);

            final MessageInfo messageInfo = mock(MessageInfo.class);

            final HttpServletRequest req = mockRequestWithCurrentUrl();
            assertEquals("/foo.jsp", new String(base64urlDecode(req.getParameter("state"))));
            when(messageInfo.getRequestMessage()).thenReturn(req);

            final Subject client = new Subject();

            final HttpServletResponse resp = mockResponse();
            when(messageInfo.getResponseMessage()).thenReturn(resp);

            assertEquals(AuthStatus.SEND_SUCCESS, module.validateRequest(messageInfo, client, null));

            validateResponse(resp);
        }
    }

    private void validateResponse(final HttpServletResponse resp) throws GeneralSecurityException,
        IOException {

        final ArgumentCaptor<Cookie> cookieCapture = ArgumentCaptor.forClass(Cookie.class);
        verify(resp, times(3)).addCookie(cookieCapture.capture());
        final Cookie nonceCookie = cookieCapture.getAllValues()
            .get(0);
        assertEquals(OpenIdConnectAuthModule.NET_TRAJANO_AUTH_NONCE, nonceCookie.getName());
        assertEquals(nonceCookie.getValue(), "");

        final Cookie cookie = cookieCapture.getAllValues()
            .get(1);
        assertEquals(OpenIdConnectAuthModule.NET_TRAJANO_AUTH_ID, cookie.getName());
        tokenCookie = new TokenCookie(cookie.getValue(), secretKey);

        assertEquals("https://accounts.google.com", tokenCookie.getIdToken()
            .getString("iss"));
        final String nonceCookieValue = base64urlEncode(CipherUtil.encrypt(tokenCookie.getIdToken()
            .getString("nonce")
            .getBytes(), secretKey));
        assertNotNull(nonceCookieValue);
        assertEquals(8, base64urlDecode(tokenCookie.getIdToken()
            .getString("nonce")).length);

        ageCookie = cookieCapture.getAllValues()
            .get(2);
        assertEquals(OpenIdConnectAuthModule.NET_TRAJANO_AUTH_AGE, ageCookie.getName());

        final ArgumentCaptor<String> redirectUrl = ArgumentCaptor.forClass(String.class);
        verify(resp).sendRedirect(redirectUrl.capture());
        finalUrl = redirectUrl.getValue();
    }
}
