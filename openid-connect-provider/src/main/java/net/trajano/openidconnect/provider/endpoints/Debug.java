package net.trajano.openidconnect.provider.endpoints;

import javax.ejb.EJB;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

import net.trajano.openidconnect.provider.ejb.AcceptAllClientManager;

@Path("debug")
public class Debug {

    @EJB
    AcceptAllClientManager acm;

    @GET
    public Response getTokens() {

        return Response.ok(acm.codeToTokenResponse.keySet()).build();
    }
}
