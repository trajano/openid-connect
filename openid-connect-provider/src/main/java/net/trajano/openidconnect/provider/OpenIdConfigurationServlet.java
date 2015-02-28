package net.trajano.openidconnect.provider;

import java.io.IOException;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObjectBuilder;
import javax.servlet.ServletException;
import javax.servlet.ServletRegistration;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.provider.internal.ProviderV1;

@Stateless
@WebServlet(urlPatterns = "/.well-known/openid-configuration")
public class OpenIdConfigurationServlet extends HttpServlet {

    private static final JsonArray RESPONSE_TYPES_SUPPORTED = Json.createArrayBuilder()
            .add("code")
            .add("id_token")
            .add("token id_token")
            .build();

    /**
     *
     */
    private static final long serialVersionUID = 6132560325834237652L;

    /**
     * Authorization endpoint mapping that is built during {@link #init()}
     */
    private String authorizationMapping;

    /**
     * Issuer override. If not it will be the URI without the port and the
     * scheme replaced with HTTPS.
     */
    private String issuer;

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

    @Override
    protected void doGet(final HttpServletRequest request,
            final HttpServletResponse resp) throws ServletException,
            IOException {

        final JsonObjectBuilder builder = Json.createObjectBuilder();

        // The value will be replaced by replacePath
        if (issuer == null) {
            builder.add("issuer", UriBuilder.fromUri(request.getRequestURL()
                    .toString())
                    .scheme("https")
                    .port(-1)
                    .replacePath("")
                    .build()
                    .toASCIIString());
        } else {
            builder.add("issuer", issuer);
        }
        final UriBuilder uriBuilder = UriBuilder.fromUri(request.getRequestURL()
                .toString());

        builder.add("jwks_uri", uriBuilder.replacePath(request.getContextPath() + "/jwks.json")
                .build()
                .toASCIIString());
        builder.add("authorization_endpoint", uriBuilder.replacePath(request.getContextPath() + authorizationMapping)
                .build()
                .toASCIIString());
        if (revocationMapping != null) {
            builder.add("revocation_endpoint", uriBuilder.replacePath(request.getContextPath() + revocationMapping)
                    .build()
                    .toASCIIString());
        }
        builder.add("token_endpoint", uriBuilder.replacePath(request.getContextPath() + tokenMapping)
                .build()
                .toASCIIString());

        final JsonArrayBuilder scopesSupportedBuilder = Json.createArrayBuilder();
        scopesSupportedBuilder.add("openid");
        scopesSupportedBuilder.add("email");

        if (userinfoMapping != null) {
            builder.add("userinfo_endpoint", uriBuilder.replacePath(request.getContextPath() + userinfoMapping)
                    .build()
                    .toASCIIString());
            scopesSupportedBuilder.add("profile");
        }

        builder.add("scopes_supported", scopesSupportedBuilder);
        builder.add("response_types_supported", RESPONSE_TYPES_SUPPORTED);

        resp.setHeader("Cache-Control", "public, max-age=86400");
        resp.setHeader("ETag", keyProvider.getKid());
        resp.setContentType(MediaType.APPLICATION_JSON);
        final String configurationJson = builder.build()
                .toString();
        resp.setContentLength(configurationJson.length());
        resp.getWriter()
                .write(configurationJson);

    }

    /**
     * Determines the endpoints for OAuth2 based on the mappings specified in
     * the {@link ServletRegistration}s.
     */
    @Override
    public void init() throws ServletException {

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

        if (keyProvider == null) {
            throw new ServletException("key provider3 is not injected");
        }
    }

}
