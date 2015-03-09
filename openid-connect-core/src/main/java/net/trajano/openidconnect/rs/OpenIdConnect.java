package net.trajano.openidconnect.rs;

import java.util.Arrays;
import java.util.Collection;

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
