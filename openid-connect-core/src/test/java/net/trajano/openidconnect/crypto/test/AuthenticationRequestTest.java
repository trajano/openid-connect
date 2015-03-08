package net.trajano.openidconnect.crypto.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.UUID;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.BadRequestException;

import net.trajano.openidconnect.auth.AuthenticationRequest;
import net.trajano.openidconnect.core.OpenIdConnectKey;
import net.trajano.openidconnect.core.Scope;
import net.trajano.openidconnect.crypto.JWE;
import net.trajano.openidconnect.crypto.JsonWebAlgorithm;
import net.trajano.openidconnect.crypto.JsonWebKey;
import net.trajano.openidconnect.crypto.JsonWebKeySet;
import net.trajano.openidconnect.crypto.JsonWebToken;
import net.trajano.openidconnect.crypto.RsaWebKey;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class AuthenticationRequestTest {

    private JsonWebKeySet jwks;

    private JsonWebKeySet privateJwks;

    @Before
    public void buildJwks() throws Exception {

        jwks = new JsonWebKeySet();
        privateJwks = new JsonWebKeySet();

        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        for (int i = 0; i < 10; ++i) {
            final KeyPair keyPair = keyPairGenerator.generateKeyPair();

            final String keyId = UUID.randomUUID()
                    .toString();
            final RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
            final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

            JsonWebKey jwk = new RsaWebKey(keyId, publicKey);
            jwk.setAlg(JsonWebAlgorithm.RS256);
            jwks.add(jwk);

            JsonWebKey privateJwk = new RsaWebKey(keyId, privateKey);
            privateJwk.setAlg(JsonWebAlgorithm.RS256);
            privateJwks.add(privateJwk);

        }

    }

    @Test
    public void testMaxAge() throws Exception {

        JsonObjectBuilder b = Json.createObjectBuilder();
        b.add(OpenIdConnectKey.MAX_AGE, 523);
        b.add(OpenIdConnectKey.RESPONSE_TYPE, "code");
        b.add(OpenIdConnectKey.SCOPE, "openid profile");
        b.add(OpenIdConnectKey.REDIRECT_URI, "http://foo");
        b.add(OpenIdConnectKey.CLIENT_ID, "barbar");
        HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
        final JsonObject requestObject = b.build();
        final JsonWebKey jwk = jwks.getKeys()[5];
        final String encrypted = JWE.encrypt(requestObject, jwk, JsonWebAlgorithm.RSA_OAEP, JsonWebAlgorithm.A256CBC);
        JWE.decrypt(encrypted, privateJwks.getJwk(jwk.getKid()));
        when(req.getParameter(OpenIdConnectKey.REQUEST)).thenReturn(encrypted);
        when(req.getParameter(OpenIdConnectKey.CLIENT_ID)).thenReturn("barbar");
        when(req.getParameter(OpenIdConnectKey.SCOPE)).thenReturn("openid");
        AuthenticationRequest authReq = new AuthenticationRequest(req, privateJwks);
        assertEquals("barbar", authReq.getClientId());
        assertTrue(authReq.getScopes()
                .containsAll(Arrays.asList(Scope.openid, Scope.profile)));
        assertEquals(2, authReq.getScopes()
                .size());
    }

    @Test
    public void testMaxAgeWithNoAlgJWT() throws Exception {

        JsonObjectBuilder b = Json.createObjectBuilder();
        b.add(OpenIdConnectKey.MAX_AGE, 523);
        b.add(OpenIdConnectKey.RESPONSE_TYPE, "code");
        b.add(OpenIdConnectKey.SCOPE, "openid profile");
        b.add(OpenIdConnectKey.REDIRECT_URI, "http://foo");
        b.add(OpenIdConnectKey.CLIENT_ID, "barbar");
        HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
        final JsonObject requestObject = b.build();

        when(req.getParameter(OpenIdConnectKey.REQUEST)).thenReturn(new JsonWebToken(requestObject, false).toString());
        when(req.getParameter(OpenIdConnectKey.CLIENT_ID)).thenReturn("barbar");
        when(req.getParameter(OpenIdConnectKey.SCOPE)).thenReturn("openid");
        AuthenticationRequest authReq = new AuthenticationRequest(req, privateJwks);
        assertEquals("barbar", authReq.getClientId());
        assertTrue(authReq.getScopes()
                .containsAll(Arrays.asList(Scope.openid, Scope.profile)));
        assertEquals(2, authReq.getScopes()
                .size());
    }

    @Test
    public void testMismatch() throws Exception {

        try {
            JsonObjectBuilder b = Json.createObjectBuilder();
            b.add(OpenIdConnectKey.MAX_AGE, 523);
            b.add(OpenIdConnectKey.RESPONSE_TYPE, "code");
            b.add(OpenIdConnectKey.SCOPE, "openid profile");
            b.add(OpenIdConnectKey.REDIRECT_URI, "http://foo");
            b.add(OpenIdConnectKey.CLIENT_ID, "barbar");
            HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
            final JsonObject requestObject = b.build();
            when(req.getParameter(OpenIdConnectKey.REQUEST)).thenReturn(new JsonWebToken(requestObject, false).toString());
            when(req.getParameter(OpenIdConnectKey.CLIENT_ID)).thenReturn("foofoo");
            new AuthenticationRequest(req, privateJwks);
            fail();
        } catch (BadRequestException e) {

        }
    }
}
