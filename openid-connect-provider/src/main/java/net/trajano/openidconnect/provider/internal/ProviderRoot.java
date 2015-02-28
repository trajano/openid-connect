package net.trajano.openidconnect.provider.internal;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import net.trajano.openidconnect.provider.WellKnownOpenIdConfiguration;

@ApplicationPath("")
public class ProviderRoot extends Application {

    @Override
    public Set<Class<?>> getClasses() {

        Set<Class<?>> classes = new HashSet<>();
        classes.add(WellKnownOpenIdConfiguration.class);
        return classes;
    }
}
