package net.trajano.openidconnect.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.trajano.openidconnect.servlet.internal.AuthenticationRequestHandler;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

/**
 * <p>
 * The Authorization Endpoint performs Authentication of the End-User. This is
 * done by sending the User Agent to the Authorization Server's Authorization
 * Endpoint for Authentication and Authorization, using request parameters
 * defined by OAuth 2.0 and additional parameters and parameter values defined
 * by OpenID Connect.
 * </p>
 * <p>
 * Communication with the Authorization Endpoint MUST utilize TLS. See Section
 * 16.17 for more information on using TLS.
 * </p>
 * 
 * @author Archimedes
 */
public class AuthorizationEndpointServlet extends HttpServlet {

    private ClientManager clientManager;

    @Override
    public void init() throws ServletException {

        try {
            clientManager = (ClientManager) Class.forName(getServletConfig().getInitParameter("net.trajano.openidconnect.servlet.ClientManager"))
                    .newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            throw new ServletException(e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException {

        doPost(req, resp);
    }

    /**
     * <p>
     * An Authentication Request is an OAuth 2.0 Authorization Request that
     * requests that the End-User be authenticated by the Authorization Server.
     * </p>
     * <p>
     * Authorization Servers MUST support the use of the HTTP GET and POST
     * methods defined in RFC 2616 [RFC2616] at the Authorization Endpoint.
     * Clients MAY use the HTTP GET or POST methods to send the Authorization
     * Request to the Authorization Server. If using the HTTP GET method, the
     * request parameters are serialized using URI Query String Serialization,
     * per Section 13.1. If using the HTTP POST method, the request parameters
     * are serialized using Form Serialization, per Section 13.2.
     * </p>
     */
    @Override
    protected void doPost(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException {

        if (!req.isSecure()) {
            throw new ServletException("secure connection required");
        }
        new AuthenticationRequestHandler(req);

        Subject currentUser = SecurityUtils.getSubject();
        if (currentUser.isAuthenticated()) {

        }
    }
}
