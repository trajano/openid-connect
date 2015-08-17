package net.trajano.openidconnect.provider.endpoints;

import static java.net.URI.create;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.enterprise.context.RequestScoped;
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

import net.trajano.openidconnect.auth.ResponseMode;
import net.trajano.openidconnect.core.OpenIdProviderConfiguration;
import net.trajano.openidconnect.core.Scope;
import net.trajano.openidconnect.core.SubjectIdentifierType;
import net.trajano.openidconnect.core.TokenEndPointAuthMethod;
import net.trajano.openidconnect.crypto.JsonWebAlgorithm;
import net.trajano.openidconnect.provider.spi.KeyProvider;
import net.trajano.openidconnect.provider.spi.UserinfoProvider;
import net.trajano.openidconnect.token.GrantType;

@Path("openid-configuration")
@RequestScoped
public class WellKnownOpenIdConfiguration {

    public static final String CODE = "code";

    public static final String CODE_ID_TOKEN = "code id_token";

    public static final String CODE_ID_TOKEN_TOKEN = "code id_token token";

    public static final String CODE_TOKEN = "code token";

    public static final String ID_TOKEN = "id_token";

    public static final String ID_TOKEN_TOKEN = "id_token token";

    /**
     * Authorization endpoint mapping that is built during {@link #init()}
     */
    private String authorizationMapping;

    private String endSessionMapping;

    /**
     * JWKS URI mapping that is built during {@link #init()}
     */
    private String jwksMapping;

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

    private UserinfoProvider userinfoProvider;

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
        endSessionMapping = applicationPath + "/end";

    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response op(@Context final HttpServletRequest request) {

        final OpenIdProviderConfiguration openIdConfiguration = new OpenIdProviderConfiguration();

        final UriBuilder baseUri = UriBuilder.fromUri(create(request.getRequestURL()
            .toString()))
            .scheme("https")
            .replaceQuery(null)
            .fragment(null);
        openIdConfiguration.setIssuer(baseUri.replacePath(request.getContextPath())
            .build());
        openIdConfiguration.setJwksUri(baseUri.replacePath(request.getContextPath() + jwksMapping)
            .build());
        openIdConfiguration.setAuthorizationEndpoint(baseUri.replacePath(request.getContextPath() + authorizationMapping)
            .build());
        openIdConfiguration.setRevocationEndpoint(baseUri.replacePath(request.getContextPath() + revocationMapping)
            .build());
        openIdConfiguration.setTokenEndpoint(baseUri.replacePath(request.getContextPath() + tokenMapping)
            .build());
        openIdConfiguration.setEndSessionEndpoint(baseUri.replacePath(request.getContextPath() + endSessionMapping)
            .build());
        openIdConfiguration.setUserinfoEndpoint(baseUri.replacePath(request.getContextPath() + userinfoMapping)
            .build());

        final Scope[] scopesSupported = userinfoProvider.scopesSupported();
        final Scope[] scopes = new Scope[scopesSupported.length + 1];
        System.arraycopy(scopesSupported, 0, scopes, 1, scopesSupported.length);
        scopes[0] = Scope.openid;
        openIdConfiguration.setScopesSupported(scopes);

        final String[] claimsSupported = userinfoProvider.claimsSupported();
        final String[] claims = new String[claimsSupported.length + 3];
        claims[0] = "sub";
        claims[1] = "iss";
        claims[2] = "auth_time";
        System.arraycopy(claimsSupported, 0, claims, 3, claimsSupported.length);
        openIdConfiguration.setClaimsSupported(claims);

        openIdConfiguration.setResponseTypesSupported(CODE, ID_TOKEN, ID_TOKEN_TOKEN, CODE_ID_TOKEN, CODE_TOKEN, CODE_ID_TOKEN_TOKEN);
        openIdConfiguration.setRequestParameterSupported(true);
        openIdConfiguration.setGrantTypesSupported(GrantType.authorization_code, GrantType.implicit);
        openIdConfiguration.setRequestUriParameterSupported(false);
        openIdConfiguration.setSubjectTypesSupported(SubjectIdentifierType.PUBLIC);
        openIdConfiguration.setTokenEndpointAuthMethodsSupported(TokenEndPointAuthMethod.client_secret_basic, TokenEndPointAuthMethod.client_secret_post);
        openIdConfiguration.setIdTokenSigningAlgValuesSupported(JsonWebAlgorithm.getSigAlgorithms());
        openIdConfiguration.setRequestObjectEncryptionAlgValuesSupported(JsonWebAlgorithm.getKexAlgorithms());
        openIdConfiguration.setRequestObjectEncryptionEncValuesSupported(JsonWebAlgorithm.getEncAlgorithms());
        openIdConfiguration.setResponseModesSupported(ResponseMode.fragment, ResponseMode.query, ResponseMode.form_post);

        final CacheControl cacheControl = new CacheControl();
        cacheControl.setPrivate(false);
        cacheControl.setMaxAge(86400);

        return Response.ok(openIdConfiguration)
            .cacheControl(cacheControl)
            .tag(keyProvider.getSecretKeyId())
            .build();

    }

    @EJB
    public void setKeyProvider(final KeyProvider keyProvider) {

        this.keyProvider = keyProvider;
    }

    @EJB
    public void setUserinfoProvider(final UserinfoProvider userinfoProvider) {

        this.userinfoProvider = userinfoProvider;
    }

}
