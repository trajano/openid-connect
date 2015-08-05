/**
 * 
 */
package net.trajano.openidconnect.jaspic;

import java.net.URI;

/**
 * Remote interface for EJBs providing the module configuration. This is
 * utilized by the Initializer.
 * 
 * @author Archimedes Trajano
 */
public interface OpenIdConnectModuleConfigProviderRemote {

    String getClientId();

    String getClientSecret();

    boolean isCertificateCheckDisabled();

    String getScope();

    URI getIssuerUri();
}
