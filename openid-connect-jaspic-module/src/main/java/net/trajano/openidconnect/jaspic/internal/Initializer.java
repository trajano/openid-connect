package net.trajano.openidconnect.jaspic.internal;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.message.config.AuthConfigFactory;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import net.trajano.auth.AuthModuleConfigProvider;
import net.trajano.auth.OAuthModule;
import net.trajano.auth.OpenIDConnectAuthModule;

/**
 * This initializes the OpenID Connector JASPIC module and registers itself as
 * the OAuth provider.
 */
@WebListener
public class Initializer implements ServletContextListener {

    @Override
    public void contextDestroyed(final ServletContextEvent sce) {

        AuthConfigFactory.getFactory()
                .removeRegistration(registrationID);
    }

    /**
     * Keys required by the OpenID Connect JASPIC module. It is expected that
     * the web.xml contains &gt;
     */
    private static final String[] KEYS = { OAuthModule.CLIENT_ID_KEY, OAuthModule.CLIENT_SECRET_KEY, OpenIDConnectAuthModule.ISSUER_URI_KEY };

    /**
     * Keys that are optional by the OpenID Connect JASPIC module.
     */
    private static final String[] OPTIONAL_KEYS = { OAuthModule.DISABLE_CERTIFICATE_CHECKS_KEY, };

    @Override
    public void contextInitialized(final ServletContextEvent sce) {

        final Map<String, String> options = new HashMap<>();
        for (String key : KEYS) {
            String initParameter = sce.getServletContext()
                    .getInitParameter(key);
            if (initParameter == null)
                throw new RuntimeException("Missing required context parameter " + key);
            options.put(key, initParameter);
        }
        for (String key : OPTIONAL_KEYS) {
            String initParameter = sce.getServletContext()
                    .getInitParameter(key);
            if (initParameter != null)
                options.put(key, initParameter);
        }
        options.put(AuthModuleConfigProvider.SERVER_AUTH_MODULE_CLASS, OpenIDConnectAuthModule.class.getName());

        options.put("cookie_context", sce.getServletContext()
                .getContextPath() + "/");
        options.put("scope", "openid profile email");
        options.put("redirection_endpoint", sce.getServletContext()
                .getContextPath() + "/oauth2");
        options.put("token_uri", sce.getServletContext()
                .getContextPath() + "/token");
        options.put("userinfo_uri", sce.getServletContext()
                .getContextPath() + "/userinfo");
        options.put(OAuthModule.LOGOUT_GOTO_URI_KEY, sce.getServletContext()
                .getContextPath() + "/");
        options.put(OAuthModule.LOGOUT_URI_KEY, sce.getServletContext()
                .getContextPath() + "/logout");
        registrationID = AuthConfigFactory.getFactory()
                .registerConfigProvider(new AuthModuleConfigProvider(options, null), "HttpServlet", null, null);

    }

    /**
     * A String identifier assigned by the {@link AuthConfigFactory} to the
     * provider registration, and is used to remove the registration from the
     * factory.
     */
    private String registrationID;
}
