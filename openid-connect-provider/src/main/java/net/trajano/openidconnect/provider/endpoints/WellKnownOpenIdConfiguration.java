package net.trajano.openidconnect.provider.endpoints;

import static java.net.URI.create;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;
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

import com.google.gson.Gson;

import net.trajano.openidconnect.core.OpenIdProviderConfiguration;
import net.trajano.openidconnect.crypto.JsonWebAlgorithm;
import net.trajano.openidconnect.provider.spi.KeyProvider;
import net.trajano.openidconnect.provider.spi.UserinfoProvider;
import net.trajano.openidconnect.provider.type.GrantType;
import net.trajano.openidconnect.provider.type.OpenidProviderMetadata;
import net.trajano.openidconnect.provider.type.ResponseModesSupported;
import net.trajano.openidconnect.provider.type.Scope;
import net.trajano.openidconnect.provider.type.SubjectTypesSupported;
import net.trajano.openidconnect.provider.type.TokenEndpointAuthMethodsSupported;

@Path("openid-configuration")
@Stateless
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

        final UriBuilder baseUri = UriBuilder.fromUri(create(request.getRequestURL()
            .toString()))
            .scheme("https")
            .replaceQuery(null)
            .fragment(null);

        final Set<Scope> scopesSupported = new HashSet<>(userinfoProvider.scopesSupported());
        scopesSupported.add(Scope.OPENID);

        final Set<String> claimsSupported = new HashSet<>(userinfoProvider.claimsSupported());
        claimsSupported.add("sub");
        claimsSupported.add("iss");
        claimsSupported.add("auth_time");

        final OpenidProviderMetadata metaData = new OpenidProviderMetadata()
            .withIssuer(baseUri.replacePath(request.getContextPath()).build().toASCIIString())
            .withJwksUri(baseUri.replacePath(request.getContextPath() + jwksMapping).build())
            .withAuthorizationEndpoint(baseUri.replacePath(request.getContextPath() + authorizationMapping).build())
            .withRevocationEndpoint(baseUri.replacePath(request.getContextPath() + revocationMapping).build())
            .withTokenEndpoint(baseUri.replacePath(request.getContextPath() + tokenMapping).build())
            .withUserinfoEndpoint(baseUri.replacePath(request.getContextPath() + userinfoMapping).build())
            .withEndSessionEndpoint(baseUri.replacePath(request.getContextPath() + endSessionMapping).build())
            .withScopesSupported(scopesSupported)
            .withClaimsSupported(claimsSupported)
            .withResponseTypesSupported(new HashSet<>(Arrays.asList(CODE, ID_TOKEN, ID_TOKEN_TOKEN, CODE_ID_TOKEN, CODE_TOKEN, CODE_ID_TOKEN_TOKEN)))
            .withRequestParameterSupported(true)
            .withGrantTypesSupported(new HashSet<>(Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT)))
            .withRequestUriParameterSupported(false)
            .withSubjectTypesSupported(new HashSet<>(Arrays.asList(SubjectTypesSupported.PUBLIC)))
            .withTokenEndpointAuthMethodsSupported(new HashSet<>(Arrays.asList(TokenEndpointAuthMethodsSupported.CLIENT_SECRET_BASIC, TokenEndpointAuthMethodsSupported.CLIENT_SECRET_POST)))
            .withResponseModesSupported(new HashSet<>(Arrays.asList(ResponseModesSupported.FRAGMENT, ResponseModesSupported.QUERY, ResponseModesSupported.FORM_POST)));

        final OpenIdProviderConfiguration openIdConfiguration = new OpenIdProviderConfiguration();

        openIdConfiguration.setIdTokenSigningAlgValuesSupported(JsonWebAlgorithm.getSigAlgorithms());
        openIdConfiguration.setRequestObjectEncryptionAlgValuesSupported(JsonWebAlgorithm.getKexAlgorithms());
        openIdConfiguration.setRequestObjectEncryptionEncValuesSupported(JsonWebAlgorithm.getEncAlgorithms());

        final CacheControl cacheControl = new CacheControl();
        cacheControl.setPrivate(false);
        cacheControl.setMaxAge(86400);

        return Response.ok(new Gson().toJson(metaData))
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
