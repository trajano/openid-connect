package net.trajano.openidconnect.servlet;

import java.io.IOException;
import java.util.Iterator;

import javax.ejb.EJB;
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
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.servlet.internal.KeyProvider;

@WebServlet(urlPatterns = "/.well-known/openid-configuration", loadOnStartup = 1)
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
     * End session endpoint mapping that is built during {@link #init()}
     */
    private String revocationMapping;

    /**
     * Issuer override. If not it will be the URI without the port and the
     * scheme replaced with HTTPS.
     */
    private String issuer;

    /**
     * JWKS URI mapping that is built during {@link #init()}
     */
    private String jwksMapping;

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

    @EJB
    private KeyProvider keyProvider;

    /**
     * Gets the one and only one mapping for the {@link ServletRegistration}.
     *
     * @param servletRegistration
     * @throws ServletException
     */
    private String getMappedUri(final ServletRegistration servletRegistration) throws ServletException {

        final Iterator<String> iterator = servletRegistration.getMappings()
                .iterator();
        final String mapping = iterator.next();
        if (iterator.hasNext()) {
            throw new ServletException("Servlet " + servletRegistration.getClassName() + " has more than one mapping");
        } else if (!mapping.startsWith("/")) {
            throw new ServletException("mapping is expected to start with /");
        }
        return getServletContext().getContextPath() + mapping;
    }

    /**
     * Determines the endpoints for OAuth2 based on the mappings specified in
     * the {@link ServletRegistration}s.
     */
    @Override
    public void init() throws ServletException {

        for (final ServletRegistration servletRegistration : getServletContext().getServletRegistrations()
                .values()) {
            try {
                if (AuthorizationEndpointServlet.class.isAssignableFrom(Class.forName(servletRegistration.getClassName()))) {
                    authorizationMapping = getMappedUri(servletRegistration);
                }
            } catch (final ClassNotFoundException e) {
                log("Unable to get class " + servletRegistration.getClassName(), e);
            }
        }
    }

}
