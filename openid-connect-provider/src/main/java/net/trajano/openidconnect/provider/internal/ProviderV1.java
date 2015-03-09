package net.trajano.openidconnect.provider.internal;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import net.trajano.openidconnect.provider.endpoints.Jwks;
import net.trajano.openidconnect.provider.endpoints.TokenEndpoint;
import net.trajano.openidconnect.provider.endpoints.UserinfoEndpoint;
import net.trajano.openidconnect.rs.IdTokenProvider;
import net.trajano.openidconnect.rs.JsonWebKeyProvider;
import net.trajano.openidconnect.rs.JsonWebKeySetProvider;

@ApplicationPath("V1")
public class ProviderV1 extends Application {

    @Override
    public Set<Class<?>> getClasses() {

        final Set<Class<?>> classes = new HashSet<>();
        classes.add(TokenEndpoint.class);
        classes.add(IdTokenProvider.class);
        classes.add(Jwks.class);
        classes.add(JsonWebKeyProvider.class);
        classes.add(JsonWebKeySetProvider.class);
        classes.add(UserinfoEndpoint.class);
        return classes;
    }
}
