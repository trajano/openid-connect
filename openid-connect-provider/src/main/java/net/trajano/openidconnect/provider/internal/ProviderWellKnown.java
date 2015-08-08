package net.trajano.openidconnect.provider.internal;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

@ApplicationPath(".well-known")
public class ProviderWellKnown extends Application {

    //    @Override
    //    public Set<Class<?>> getClasses() {
    //
    //        final Set<Class<?>> classes = new HashSet<>();
    //        classes.add(WellKnownOpenIdConfiguration.class);
    //        return classes;
    //    }

}
