package net.trajano.openidconnect.provider;

import javax.ejb.EJB;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

/**
 * <p>
 * The UserInfo Endpoint is an OAuth 2.0 Protected Resource that returns Claims
 * about the authenticated End-User. To obtain the requested Claims about the
 * End-User, the Client makes a request to the UserInfo Endpoint using an Access
 * Token obtained through OpenID Connect Authentication. These Claims are
 * normally represented by a JSON object that contains a collection of name and
 * value pairs for the Claims.
 * </p>
 * <p>
 * Communication with the UserInfo Endpoint MUST utilize TLS. See Section 16.17
 * for more information on using TLS.
 * </p>
 * <p>
 * The UserInfo Endpoint MUST support the use of the HTTP GET and HTTP POST
 * methods defined in RFC 2616 [RFC2616].
 * </p>
 * <p>
 * The UserInfo Endpoint MUST accept Access Tokens as OAuth 2.0 Bearer Token
 * Usage [RFC6750].
 * </p>
 * <p>
 * The UserInfo Endpoint SHOULD support the use of Cross Origin Resource Sharing
 * (CORS) [CORS] and or other methods as appropriate to enable Java Script
 * Clients to access the endpoint.
 * </p>
 */
@Path("profile")
public class UserinfoEndpoint {

    private Authenticator authenticator;
    private ClientManager clientManager;

    /**
     * <p>
     * The Client sends the UserInfo Request using either HTTP GET or HTTP POST.
     * The Access Token obtained from an OpenID Connect Authentication Request
     * MUST be sent as a Bearer Token, per Section 2 of OAuth 2.0 Bearer Token
     * Usage [RFC6750].
     * </p>
     * <p>
     * It is RECOMMENDED that the request use the HTTP GET method and the Access
     * Token be sent using the Authorization header field.
     * </p>
     * 
     * @param req
     * @return
     */
    @GET
    public Response getOp(@Context HttpServletRequest req) {

        return op(req);
    }

    @POST
    public Response op(@Context HttpServletRequest req) {

        return null;
    }

    @EJB
    public void setAuthenticator(final Authenticator authenticator) {
    
        this.authenticator = authenticator;
    }

    @EJB
    public void setClientManager(final ClientManager clientManager) {
    
        this.clientManager = clientManager;
    }
}
