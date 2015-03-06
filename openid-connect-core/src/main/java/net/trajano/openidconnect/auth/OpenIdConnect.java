package net.trajano.openidconnect.auth;

import java.util.Arrays;
import java.util.Collection;

import net.trajano.openidconnect.rs.AuthenticationRequestJsonProvider;

/**
 * Utility class to help in registrations.
 * 
 * @author Archimedes
 */
public class OpenIdConnect {

    public static final Collection<Class<?>> jaxRsProviders() {

        return Arrays.asList(new Class<?>[] { AuthenticationRequestJsonProvider.class });
    }
}
