package net.trajano.openidconnect.jaspic.internal;

import java.util.HashMap;
import java.util.Map;

import javax.annotation.Resource;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import net.trajano.openidconnect.jaspic.OpenIDConnectAuthModule;
import net.trajano.openidconnect.jaspic.OpenIDConnectModuleConfigProvider;

/**
 * This initializes the OpenID Connector JASPIC module and registers itself as
 * the OAuth provider.
 */
@WebListener
public class Initializer implements ServletContextListener {

    /**
     * asadmin set-web-env-entry
     * --name=net.trajano.openidconnect.jaspic/client_id --value=asmin
     * --type=java.lang.String
     * openid-connect-sample/openid-connect-jaspic-sample-1.0.0-SNAPSHOT.war
     */
    @Resource(name = "net.trajano.openidconnect.jaspic/client_id", description = "Client ID")
    private String clientId;

    @Resource(name = "net.trajano.openidconnect.jaspic/client_secret", description = "Client Secret")
    private String clientSecret;

    @Resource(name = "net.trajano.openidconnect.jaspic/disable_certificate_checks", description = "Disable certificate checks. (optional, defaults to false)")
    private String disableCertificateChecks = Boolean.FALSE.toString();

    @Resource(name = "net.trajano.openidconnect.jaspic/issuer_uri", description = "Issuer URI")
    private String issuerUri;

    @Resource(name = "net.trajano.openidconnect.jaspic/scope", description = "Scope. (optional, defaults to 'openid profile email')")
    private String scope = "openid profile email";

    /**
     * A String identifier assigned by the {@link AuthConfigFactory} to the
     * provider registration, and is used to remove the registration from the
     * factory.
     */
    private String registrationID;

    @Override
    public void contextDestroyed(final ServletContextEvent sce) {

        AuthConfigFactory.getFactory()
                .removeRegistration(registrationID);
    }

    @Override
    public void contextInitialized(final ServletContextEvent sce) {

        final Map<String, String> options = new HashMap<>();

        options.put(OpenIDConnectAuthModule.CLIENT_ID_KEY, clientId);
        options.put(OpenIDConnectAuthModule.CLIENT_SECRET_KEY, clientSecret);
        options.put(OpenIDConnectAuthModule.DISABLE_CERTIFICATE_CHECKS_KEY, disableCertificateChecks);
        options.put(OpenIDConnectAuthModule.ISSUER_URI_KEY, issuerUri);

        final String contextPath = sce.getServletContext()
                .getContextPath();
        final String rootPath = contextPath + "/";
        options.put("cookie_context", rootPath);
        options.put("scope", scope);
        options.put("redirection_endpoint", contextPath + "/cb");
        options.put("token_uri", contextPath + "/token");
        options.put("userinfo_uri", contextPath + "/userinfo");
        options.put(OpenIDConnectAuthModule.LOGOUT_GOTO_URI_KEY, rootPath);
        options.put(OpenIDConnectAuthModule.LOGOUT_URI_KEY, contextPath + "/logout");

        registrationID = AuthConfigFactory.getFactory()
                .registerConfigProvider(new OpenIDConnectModuleConfigProvider(options, null), "HttpServlet", null, null);

    }
}
