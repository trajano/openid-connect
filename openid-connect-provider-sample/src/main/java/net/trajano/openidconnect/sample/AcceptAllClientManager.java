package net.trajano.openidconnect.sample;

import java.net.URI;
import java.util.Date;
import java.util.Locale;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.json.Json;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.auth.AuthenticationRequest;
import net.trajano.openidconnect.core.OpenIdConnectKey;
import net.trajano.openidconnect.core.Scope;
import net.trajano.openidconnect.crypto.Encoding;
import net.trajano.openidconnect.provider.spi.Authenticator;
import net.trajano.openidconnect.provider.spi.ClientManager;
import net.trajano.openidconnect.provider.spi.TokenProvider;
import net.trajano.openidconnect.provider.spi.UserinfoProvider;
import net.trajano.openidconnect.token.IdToken;
import net.trajano.openidconnect.userinfo.Userinfo;

@Stateless
public class AcceptAllClientManager implements ClientManager, Authenticator, UserinfoProvider {

    @EJB
    private TokenProvider tp;

    @Override
    public URI authenticate(final AuthenticationRequest authenticationRequest,
            final String requestJwt,
            final HttpServletRequest req,
            final UriBuilder contextUriBuilder) {

        return contextUriBuilder.path("login.jsp")
                .queryParam(OpenIdConnectKey.REQUEST, requestJwt)
                .build();
    }

    @Override
    public String authenticateClient(final String clientId,
            final String clientSecret) {

        return clientId;
    }

    @Override
    public Userinfo getUserinfo(final IdToken idToken) {

        final Userinfo userinfo = new Userinfo();
        userinfo.setSub(idToken.getSub());
        userinfo.setUpdatedAt(new Date());
        userinfo.setEmail(Encoding.base64urlDecodeToString(idToken.getSub()));
        userinfo.setEmailVerified(true);
        userinfo.setName(idToken.getSub());
        userinfo.setGivenName(idToken.getSub());
        userinfo.setFamilyName(idToken.getSub());
        userinfo.setMiddleName(idToken.getSub());
        userinfo.setNickname(idToken.getSub());
        userinfo.setWebsite("http://www.trajano.net/");
        userinfo.setPicture("picture");
        userinfo.setGender("male");
        userinfo.setAddress(Json.createObjectBuilder()
                .add("street", "panay")
                .build());
        userinfo.setProfile("profile");
        userinfo.setBirthdate("1970-01-01");
        userinfo.setZoneinfo("zoneinfo");
        userinfo.setLocale(Locale.ENGLISH);
        userinfo.setPreferredUsername("foobar");
        userinfo.setPhoneNumber("444-111-2222");
        userinfo.setPhoneNumberVerified(true);

        return userinfo;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isAuthenticated(final HttpServletRequest req) {

        return req.getSession()
                .getAttribute("sub") != null;
    }

    @Override
    public boolean isRedirectUriValidForClient(final String clientId,
            final URI redirectUri) {

        return true;
    }

    @Override
    public String getSubject(HttpServletRequest req) {

        return (String) req.getSession()
                .getAttribute("sub");
    }

    @Override
    public boolean isImplicitConsent(String clientId) {

        return false;
    }

    @Override
    public URI consent(AuthenticationRequest authenticationRequest,
            String requestJwt,
            HttpServletRequest req,
            UriBuilder contextUriBuilder) {

        return contextUriBuilder.path("doConsent")
                .queryParam(OpenIdConnectKey.REQUEST, requestJwt)
                .build();
    }

    @Override
    public boolean isPostLogoutRedirectUriValidForClient(String azp,
            URI postLogoutRedirectUri) {

        return true;
    }

    @Override
    public URI logout(String nonce,
            IdToken idToken,
            String state,
            URI postLogoutRedirectUri,
            HttpServletRequest req,
            UriBuilder contextUriBuilder) {

        return contextUriBuilder.path("logout.jsp")
                .queryParam("nonce", nonce)
                .build();
    }

    @Override
    public void endSession(HttpServletRequest req) {

    }

    @Override
    public Scope[] scopesSupported() {

        return new Scope[] { Scope.phone, Scope.email, Scope.address, Scope.profile };
    }

    @Override
    public String[] claimsSupported() {

        return new String[] { "sub", "email", "email_verified", "updated_at", "name", "given_name", "family_name", "middle_name", "nickname", "website", "zoneinfo", "gender", "profile", "picture", "birthdate", "locale", "preferrred_username", "address", "phone_number", "phone_number_verified" };
    }

}
