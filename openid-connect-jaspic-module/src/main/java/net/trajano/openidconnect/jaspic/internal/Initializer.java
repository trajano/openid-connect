package net.trajano.openidconnect.jaspic.internal;

import static net.trajano.openidconnect.core.OpenIdConnectKey.CLIENT_ID;
import static net.trajano.openidconnect.core.OpenIdConnectKey.CLIENT_SECRET;

import java.util.HashMap;
import java.util.Map;

import javax.annotation.Resource;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import net.trajano.openidconnect.jaspic.OpenIdConnectAuthModule;
import net.trajano.openidconnect.jaspic.OpenIdConnectModuleConfigProvider;

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

        options.put(CLIENT_ID, clientId);
        options.put(CLIENT_SECRET, clientSecret);
        options.put(OpenIdConnectAuthModule.DISABLE_CERTIFICATE_CHECKS_KEY, disableCertificateChecks);
        options.put(OpenIdConnectAuthModule.ISSUER_URI_KEY, issuerUri);

        final String contextPath = sce.getServletContext()
                .getContextPath();
        final String rootPath = contextPath + "/";
        options.put("cookie_context", rootPath);
        options.put("scope", scope);
        options.put("redirection_endpoint", contextPath + "/cb");
        options.put("logout_redirection_endpoint", contextPath + "/cblogout");
        options.put("token_uri", contextPath + "/token");
        options.put("userinfo_uri", contextPath + "/userinfo");
        // TODO make this dependent on openid configuration
        // options.put(OpenIdConnectAuthModule.LOGOUT_GOTO_URI_KEY, rootPath);
        options.put(OpenIdConnectAuthModule.LOGOUT_URI_KEY, contextPath + "/logout");

        registrationID = AuthConfigFactory.getFactory()
                .registerConfigProvider(new OpenIdConnectModuleConfigProvider(options, null), "HttpServlet", getAppContext(sce), null);

    }

    /**
     * <p>
     * The application context identifier (that is, the appContext parameter
     * value) us ed to select the AuthConfigProvider and ServerAuthConfig
     * objects for a specific application shall be the String value constructed
     * by concatenating the host name, a blank separator character, and the
     * decoded context path corresponding to the web module.
     * </p>
     * 
     * <pre>
     * AppContextID ::= hostname blank context-path
     * For example: "java-server /petstore"
     * </pre>
     * <p>
     * This profile uses the term host name to refer to the name of a logical
     * host that processes Servlet requests. Servlet requests may be directed to
     * a logical host using various physical or virtual host names or addresses,
     * and a message processing runtime may be composed of multiple logical
     * hosts . Systems or administrators that register AuthConfigProvider object
     * s with specific application context identifiers must have an ability to
     * determine the host name for which they wish to perform the registration.
     * </p>
     *
     * @see <a
     *      href="http://download.oracle.com/otn-pub/jcp/jaspic-1.0-fr-oth-JSpec/jaspic-1_0-fr-spec.pdf">JASPIC
     *      Spec section 3.2</a>
     * @return
     */
    private String getAppContext(final ServletContextEvent sce) {

        return sce.getServletContext()
                .getVirtualServerName() + " " + sce.getServletContext()
                .getContextPath();
    }
}
