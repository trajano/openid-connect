package net.trajano.openidconnect.sample;

import java.net.URI;

import javax.servlet.annotation.WebListener;

import net.trajano.openidconnect.jaspic.internal.AbstractInitializer;

/**
 * This initializes the OpenID Connector JASPIC module and registers itself as
 * the OAuth provider.
 */
@WebListener
public class Initializer extends AbstractInitializer {

    /* (non-Javadoc)
     * @see net.trajano.openidconnect.jaspic.internal.AbstractInitializer#getClientId()
     */
    @Override
    protected String getClientId() {

        return "sample_client_id";
    }

    /* (non-Javadoc)
     * @see net.trajano.openidconnect.jaspic.internal.AbstractInitializer#getClientSecret()
     */
    @Override
    protected String getClientSecret() {

        return "sample_client_secret";
    }

    /* (non-Javadoc)
     * @see net.trajano.openidconnect.jaspic.internal.AbstractInitializer#isCertificateCheckDisabled()
     */
    @Override
    protected boolean isCertificateCheckDisabled() {

        return true;
    }

    /* (non-Javadoc)
     * @see net.trajano.openidconnect.jaspic.internal.AbstractInitializer#getScope()
     */
    @Override
    protected String getScope() {

        return "openid profile email";
    }

    /* (non-Javadoc)
     * @see net.trajano.openidconnect.jaspic.internal.AbstractInitializer#getIssuerUri()
     */
    @Override
    protected URI getIssuerUri() {

        return URI.create("https://localhost:8443/");
    }
}
