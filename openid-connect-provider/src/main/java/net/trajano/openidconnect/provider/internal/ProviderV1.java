package net.trajano.openidconnect.provider.internal;

import java.util.Set;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import net.trajano.openidconnect.provider.endpoints.AuthorizationEndpoint;
import net.trajano.openidconnect.provider.endpoints.Jwks;
import net.trajano.openidconnect.provider.endpoints.TokenEndpoint;
import net.trajano.openidconnect.rs.IdTokenProvider;
import net.trajano.openidconnect.rs.JsonWebKeySetProvider;

@ApplicationPath("V1")
public class ProviderV1 extends Application {

    @Override
    public Set<Class<?>> getClasses() {

        Set<Class<?>> classes = new HashSet2<Class<?>>().put(AuthorizationEndpoint.class)
                .put(TokenEndpoint.class)
                .put(IdTokenProvider.class)
                .put(Jwks.class)
                .put(JsonWebKeySetProvider.class);
        return classes;
    }
}
