package net.trajano.openidconnect.provider.internal;

import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import net.trajano.openidconnect.crypto.JsonWebKeySetProvider;
import net.trajano.openidconnect.provider.endpoints.AuthorizationEndpoint;
import net.trajano.openidconnect.provider.endpoints.Jwks;
import net.trajano.openidconnect.provider.endpoints.TokenEndpoint;

@ApplicationPath("V1")
public class ProviderV1 extends Application {

    @Override
    public Set<Class<?>> getClasses() {

        Set<Class<?>> classes = new HashSet<>();
        classes.add(AuthorizationEndpoint.class);
        classes.add(TokenEndpoint.class);
        classes.add(Jwks.class);
        classes.add(JsonWebKeySetProvider.class);
        return classes;
    }
}
