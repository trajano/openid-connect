package net.trajano.openidconnect.provider.endpoints;

import javax.ejb.EJB;
import javax.enterprise.context.RequestScoped;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import net.trajano.openidconnect.provider.spi.KeyProvider;

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
 * @author Archimedes Trajano
 */
@Path("jwks")
@RequestScoped
public class Jwks {

    private KeyProvider keyProvider;

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
     * <p>
     * Only 3 keys are provided at a time
     * </p>
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response op() {

        final CacheControl cacheControl = new CacheControl();
        cacheControl.setPrivate(false);
        cacheControl.setMaxAge(300);

        return Response.ok(keyProvider.getJwks())
            .cacheControl(cacheControl)
            .tag(keyProvider.getSecretKeyId())
            .build();
    }

    @EJB
    public void setKeyProvider(final KeyProvider keyProvider) {

        this.keyProvider = keyProvider;
    }

}
