package net.trajano.openidconnect.sample;

import java.util.HashMap;
import java.util.Map;

import javax.ejb.Stateless;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import net.trajano.auth.AuthModuleConfigProvider;
import net.trajano.auth.OAuthModule;
import net.trajano.auth.OpenIDConnectAuthModule;

/**
 * Initializes stateless Session EJBs used by the application. Singletons are
 * not started here because they have the Startup annotation. It also
 * initializes the JASPIC context.
 */
@WebListener
@Stateless
public class Initializer implements ServletContextListener {

    @Override
    public void contextDestroyed(final ServletContextEvent sce) {

    }

    @Override
    public void contextInitialized(final ServletContextEvent sce) {

        final Map<String, String> options = new HashMap<>();
        options.put(AuthModuleConfigProvider.SERVER_AUTH_MODULE_CLASS, OpenIDConnectAuthModule.class.getName());
        options.put(OAuthModule.CLIENT_ID_KEY, "FOO");
        options.put(OAuthModule.CLIENT_SECRET_KEY, "BAR");
        options.put(OAuthModule.DISABLE_CERTIFICATE_CHECKS_KEY, "true");
        options.put(OpenIDConnectAuthModule.ISSUER_URI_KEY, "https://localhost:8181");
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
        AuthConfigFactory.getFactory()
                .registerConfigProvider(new AuthModuleConfigProvider(options, null), "HttpServlet", null, null);

    }
}
