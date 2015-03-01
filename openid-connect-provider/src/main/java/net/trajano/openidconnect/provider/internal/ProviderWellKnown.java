package net.trajano.openidconnect.provider.internal;

import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import net.trajano.openidconnect.provider.endpoints.WellKnownOpenIdConfiguration;

@ApplicationPath(".well-known")
public class ProviderWellKnown extends Application {

    @Override
    public Set<Class<?>> getClasses() {

        return new HashSet2<Class<?>>(WellKnownOpenIdConfiguration.class);
    }

}
