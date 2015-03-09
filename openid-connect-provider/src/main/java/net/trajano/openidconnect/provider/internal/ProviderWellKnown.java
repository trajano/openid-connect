package net.trajano.openidconnect.provider.internal;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import net.trajano.openidconnect.provider.endpoints.WellKnownOpenIdConfiguration;

@ApplicationPath(".well-known")
public class ProviderWellKnown extends Application {

    @Override
    public Set<Class<?>> getClasses() {

        final Set<Class<?>> classes = new HashSet<>();
        classes.add(WellKnownOpenIdConfiguration.class);
        return classes;
    }

}
