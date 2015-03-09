package net.trajano.openidconnect.provider.spi;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.ejb.Local;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

import net.trajano.openidconnect.auth.AuthenticationResponse;

/**
 * Provides authentication responses calling {@link TokenProvider} to manage the
 * tokens. It also provides methods to build the JAX-RS and HttpServlet
 * responses.
 * 
 * @author Archimedes Trajano
 */
@Local
public interface AuthenticationResponseProvider {

    /**
     * Creates a JAX-RS response.
     * 
     * @param request
     *            authentication request
     * @param subject
     *            authenticated subject to be stored by the
     *            {@link TokenProvider}
     * @return
     */
    Response buildResponse(HttpServletRequest req,
            String subject);

    /**
     * Calls for the authentication callback. Perform a redirect with the
     * authorization response data.
     *
     * @param response
     *            servlet response
     * @param request
     *            authentication request
     * @param subject
     *            authenticated subject to be stored by the
     *            {@link TokenProvider}
     * @throws IOException
     * @throws ServletException
     */
    void doCallback(HttpServletRequest req,
            HttpServletResponse response,
            String subject) throws IOException,
            ServletException;

    /**
     * Builds the authentication response object if the defined response methods
     * are not sufficient.
     * 
     * @param request
     *            authentication request
     * @param subject
     *            authenticated subject to be stored by the
     *            {@link TokenProvider}
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    AuthenticationResponse buildAuthenticationResponse(HttpServletRequest req,
            String subject) throws IOException,
            GeneralSecurityException;

}
