package net.trajano.openidconnect.provider;

import static java.net.URI.create;

import java.net.URI;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.ServletRegistration;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.core.OpenIdProviderConfiguration;
import net.trajano.openidconnect.provider.internal.HashSet2;
import net.trajano.openidconnect.provider.internal.ProviderV1;

@Stateless
@Path(".well-known/openid-configuration")
public class WellKnownOpenIdConfiguration {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response op(@Context HttpServletRequest request) {

        final OpenIdProviderConfiguration openIdConfiguration = new OpenIdProviderConfiguration();
        // The value will be replaced by replacePath
        if (issuer == null) {
            openIdConfiguration.setIssuer(UriBuilder.fromUri(request.getRequestURL()
                    .toString())
                    .scheme("https")
                    .port(-1)
                    .replacePath("")
                    .build());
        } else {
            openIdConfiguration.setIssuer(issuer);
        }
        UriBuilder baseUri = UriBuilder.fromUri(create(request.getRequestURL()
                .toString()));
        openIdConfiguration.setJwksUri(baseUri.replacePath(request.getContextPath() + jwksMapping)
                .build());
        openIdConfiguration.setAuthorizationEndpoint(baseUri.replacePath(request.getContextPath() + authorizationMapping)
                .build());
        openIdConfiguration.setRevocationEndpoint(baseUri.replacePath(request.getContextPath() + revocationMapping)
                .build());
        openIdConfiguration.setTokenEndpoint(baseUri.replacePath(request.getContextPath() + tokenMapping)
                .build());
        openIdConfiguration.setUserinfoEndpoint(baseUri.replacePath(request.getContextPath() + userinfoMapping)
                .build());
        openIdConfiguration.setScopesSupported(new HashSet2<String>("openid", "email", "profile"));
        openIdConfiguration.setResponseTypesSupported(new HashSet2<String>(CODE, ID_TOKEN, ID_TOKEN_TOKEN, CODE_ID_TOKEN, CODE_TOKEN, CODE_ID_TOKEN_TOKEN));

        CacheControl cacheControl = new CacheControl();
        cacheControl.setPrivate(false);
        cacheControl.setMaxAge(86400);

        return Response.ok(openIdConfiguration)
                .cacheControl(cacheControl)
                .tag(keyProvider.getKid())
                .build();

    }

    public static final String CODE = "code";

    public static final String ID_TOKEN = "id_token";

    public static final String ID_TOKEN_TOKEN = "id_token token";

    public static final String CODE_ID_TOKEN = "code id_token";

    public static final String CODE_TOKEN = "code token";

    public static final String CODE_ID_TOKEN_TOKEN = "code id_token token";

    /**
     * Authorization endpoint mapping that is built during {@link #init()}
     */
    private String authorizationMapping;

    /**
     * Issuer override. If not it will be the URI without the port and the
     * scheme replaced with HTTPS.
     */
    private URI issuer;

    /**
     * JWKS URI mapping that is built during {@link #init()}
     */
    private String jwksMapping;

    @EJB
    public void setKeyProvider(KeyProvider keyProvider) {

        this.keyProvider = keyProvider;
    }

    private KeyProvider keyProvider;

    /**
     * End session endpoint mapping that is built during {@link #init()}
     */
    private String revocationMapping;

    /**
     * Token endpoint mapping that is built during {@link #init()}
     */
    private String tokenMapping;

    /**
     * Userinfo endpoint mapping that is built during {@link #init()}
     */
    private String userinfoMapping;

    /**
     * Determines the endpoints for OAuth2 based on the mappings specified in
     * the {@link ServletRegistration}s.
     */
    @PostConstruct
    public void init() {

        // eventually allow for multiple for now hard code.
        final Class<? extends Application> providerClass = ProviderV1.class;
        String applicationPath = providerClass.getAnnotation(ApplicationPath.class)
                .value();
        if (!applicationPath.startsWith("/")) {
            applicationPath = "/" + applicationPath;
        }
        jwksMapping = applicationPath + "/jwks";
        authorizationMapping = applicationPath + "/auth";
        tokenMapping = applicationPath + "/token";
        userinfoMapping = applicationPath + "/profile";
        revocationMapping = applicationPath + "/revocation";

    }

}
