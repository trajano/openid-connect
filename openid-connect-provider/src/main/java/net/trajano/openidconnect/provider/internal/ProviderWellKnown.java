package net.trajano.openidconnect.provider.internal;

import java.util.HashSet;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import net.trajano.openidconnect.provider.endpoints.WellKnownOpenIdConfiguration;
import net.trajano.openidconnect.provider.spi.ClientManager;

@Stateless
@ApplicationPath(".well-known")
public class ProviderWellKnown extends Application {

    @Override
    public Set<Class<?>> getClasses() {

        Set<Class<?>> classes = new HashSet<>();
        classes.add(WellKnownOpenIdConfiguration.class);
        return classes;
    }

    private ClientManager clientManager;

    @EJB
    public void setClientManager(ClientManager clientManager) {

        this.clientManager = clientManager;
    }

    @Override
    public Set<Object> getSingletons() {

        System.out.println("HERE WITH CM=" + clientManager);
        return super.getSingletons();
        //return new HashSet2<Object>(clientManager);
    }
}
