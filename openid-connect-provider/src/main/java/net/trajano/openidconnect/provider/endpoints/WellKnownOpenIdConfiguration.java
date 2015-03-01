package net.trajano.openidconnect.provider.endpoints;

import static java.net.URI.create;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.servlet.ServletRegistration;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.core.OpenIdProviderConfiguration;
import net.trajano.openidconnect.provider.internal.HashSet2;
import net.trajano.openidconnect.provider.spi.ClientManager;
import net.trajano.openidconnect.provider.spi.KeyProvider;

@Path("openid-configuration")
public class WellKnownOpenIdConfiguration {

    private ClientManager clientManager;

    @EJB
    public void setClientManager(ClientManager clientManager) {

        this.clientManager = clientManager;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response op(@Context HttpServletRequest request) {

        final OpenIdProviderConfiguration openIdConfiguration = new OpenIdProviderConfiguration();
        openIdConfiguration.setIssuer(clientManager.getIssuer());

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
                .tag(keyProvider.getSigningKeys()[0].getKid())
                .build();

    }

    public static final String CODE = "code";

    public static final String ID_TOKEN = "id_token";

    public static final String ID_TOKEN_TOKEN = "id_token token";

    public static final String CODE_ID_TOKEN = "code id_token";

    public static final String CODE_TOKEN = "code token";

    public static final String CODE_ID_TOKEN_TOKEN = "code id_token token";

    /**
     * Authorization endpoint mapping that is built during {@link #init()}
     */
    private String authorizationMapping;

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
        String applicationPath = "V1";
        if (!applicationPath.startsWith("/")) {
            applicationPath = "/" + applicationPath;
        }
        jwksMapping = applicationPath + "/jwks";
        authorizationMapping = applicationPath + "/auth";
        tokenMapping = applicationPath + "/token";
        userinfoMapping = applicationPath + "/profile";
        revocationMapping = applicationPath + "/revocation";

        System.out.println("CM = " + clientManager);
        System.out.println("KP = " + keyProvider);
    }

}
