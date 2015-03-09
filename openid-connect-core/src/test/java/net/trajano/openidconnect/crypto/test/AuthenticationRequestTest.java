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
import net.trajano.openidconnect.crypto.JsonWebKey;
import net.trajano.openidconnect.crypto.JsonWebKeySet;
import net.trajano.openidconnect.crypto.JsonWebTokenBuilder;
import net.trajano.openidconnect.crypto.JsonWebTokenProcessor;
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

            final JsonWebKey jwk = new RsaWebKey(keyId, publicKey);
            jwk.setAlg("RS256");
            jwks.add(jwk);

            final JsonWebKey privateJwk = new RsaWebKey(keyId, privateKey);
            privateJwk.setAlg("RS256");
            privateJwks.add(privateJwk);

        }

    }

    @Test
    public void testMaxAge() throws Exception {

        final JsonObjectBuilder b = Json.createObjectBuilder();
        b.add(OpenIdConnectKey.MAX_AGE, 523);
        b.add(OpenIdConnectKey.RESPONSE_TYPE, "code");
        b.add(OpenIdConnectKey.SCOPE, "openid profile");
        b.add(OpenIdConnectKey.REDIRECT_URI, "http://foo");
        b.add(OpenIdConnectKey.CLIENT_ID, "barbar");
        final HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
        final JsonObject requestObject = b.build();
        final JsonWebKey jwk = jwks.getKeys()[5];
        final String encrypted = new JsonWebTokenBuilder().alg("RSA-OAEP").enc("A256CBC").jwk(jwk).payload(requestObject).toString();
        new JsonWebTokenProcessor(encrypted).jwks(privateJwks).getPayload();
        when(req.getParameter(OpenIdConnectKey.REQUEST)).thenReturn(encrypted);
        when(req.getParameter(OpenIdConnectKey.CLIENT_ID)).thenReturn("barbar");
        when(req.getParameter(OpenIdConnectKey.SCOPE)).thenReturn("openid");
        final AuthenticationRequest authReq = new AuthenticationRequest(req, privateJwks);
        assertEquals("barbar", authReq.getClientId());
        assertTrue(authReq.getScopes()
                .containsAll(Arrays.asList(Scope.openid, Scope.profile)));
        assertEquals(2, authReq.getScopes()
                .size());
    }

    @Test
    public void testMaxAgeWithNoAlgJWT() throws Exception {

        final JsonObjectBuilder b = Json.createObjectBuilder();
        b.add(OpenIdConnectKey.MAX_AGE, 523);
        b.add(OpenIdConnectKey.RESPONSE_TYPE, "code");
        b.add(OpenIdConnectKey.SCOPE, "openid profile");
        b.add(OpenIdConnectKey.REDIRECT_URI, "http://foo");
        b.add(OpenIdConnectKey.CLIENT_ID, "barbar");
        final HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
        final JsonObject requestObject = b.build();

        final JsonWebTokenBuilder jwtBuilder = new JsonWebTokenBuilder().payload(requestObject);
        when(req.getParameter(OpenIdConnectKey.REQUEST)).thenReturn(jwtBuilder.toString());
        when(req.getParameter(OpenIdConnectKey.CLIENT_ID)).thenReturn("barbar");
        when(req.getParameter(OpenIdConnectKey.SCOPE)).thenReturn("openid");
        final AuthenticationRequest authReq = new AuthenticationRequest(req, privateJwks);
        assertEquals("barbar", authReq.getClientId());
        assertTrue(authReq.getScopes()
                .containsAll(Arrays.asList(Scope.openid, Scope.profile)));
        assertEquals(2, authReq.getScopes()
                .size());
    }

    @Test
    public void testMismatch() throws Exception {

        try {
            final JsonObjectBuilder b = Json.createObjectBuilder();
            b.add(OpenIdConnectKey.MAX_AGE, 523);
            b.add(OpenIdConnectKey.RESPONSE_TYPE, "code");
            b.add(OpenIdConnectKey.SCOPE, "openid profile");
            b.add(OpenIdConnectKey.REDIRECT_URI, "http://foo");
            b.add(OpenIdConnectKey.CLIENT_ID, "barbar");
            final HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
            final JsonObject requestObject = b.build();
            final JsonWebTokenBuilder jwtBuilder = new JsonWebTokenBuilder().payload(requestObject);

            when(req.getParameter(OpenIdConnectKey.REQUEST)).thenReturn(jwtBuilder.toString());
            when(req.getParameter(OpenIdConnectKey.CLIENT_ID)).thenReturn("foofoo");
            new AuthenticationRequest(req, privateJwks);
            fail();
        } catch (final BadRequestException e) {

        }
    }
}
