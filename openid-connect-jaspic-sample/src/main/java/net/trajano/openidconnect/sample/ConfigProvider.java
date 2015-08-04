package net.trajano.openidconnect.sample;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;

import javax.ejb.Remote;
import javax.ejb.Stateless;

import net.trajano.openidconnect.jaspic.OpenIdConnectModuleConfigProviderRemote;

/**
 * This initializes the OpenID Connector JASPIC module and registers itself as
 * the OAuth provider.
 */
@Stateless
@Remote(OpenIdConnectModuleConfigProviderRemote.class)
public class ConfigProvider implements
    OpenIdConnectModuleConfigProviderRemote {

    /*
     * (non-Javadoc)
     * @see
     * net.trajano.openidconnect.jaspic.internal.AbstractInitializer#getClientId
     * ()
     */
    @Override
    public String getClientId() {

        return "sample_client_id";
    }

    /*
     * (non-Javadoc)
     * @see net.trajano.openidconnect.jaspic.internal.AbstractInitializer#
     * getClientSecret()
     */
    @Override
    public String getClientSecret() {

        return "sample_client_secret";
    }

    /*
     * (non-Javadoc)
     * @see net.trajano.openidconnect.jaspic.internal.AbstractInitializer#
     * getIssuerUri()
     */
    @Override
    public URI getIssuerUri() {

        try (ServerSocket s = new ServerSocket(8181)) {

        } catch (final IOException e) {
            return URI.create("https://localhost:8181");
        }
        try (ServerSocket s = new ServerSocket(9443)) {

        } catch (final IOException e) {
            return URI.create("https://localhost:9443");
        }
        throw new RuntimeException("unable to determine server port");
    }

    /*
     * (non-Javadoc)
     * @see
     * net.trajano.openidconnect.jaspic.internal.AbstractInitializer#getScope()
     */
    @Override
    public String getScope() {

        return "openid profile email";
    }

    /*
     * (non-Javadoc)
     * @see net.trajano.openidconnect.jaspic.internal.AbstractInitializer#
     * isCertificateCheckDisabled()
     */
    @Override
    public boolean isCertificateCheckDisabled() {

        return true;
    }
}
