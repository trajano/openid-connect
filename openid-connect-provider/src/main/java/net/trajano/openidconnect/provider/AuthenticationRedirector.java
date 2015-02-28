package net.trajano.openidconnect.provider;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

/**
 * Upon successful authentication, implementers are expected to invoke any of
 * the methods below. This class is meant to be injected into a servlet or REST
 * service. ?? should I move this and perhaps key provider into a EJB jar.
 * 
 * @author Archimedes Trajano
 */
public interface AuthenticationRedirector {

    void performRedirect(HttpServletResponse response,
            AuthenticationRequest request,
            String subject) throws IOException;

    Response buildResponse(AuthenticationRequest request,
            String subject);

}
