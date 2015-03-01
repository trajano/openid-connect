package net.trajano.openidconnect.provider.endpoints;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

@Path("token")
public class TokenEndpoint {

    @GET
    public Response getOp() {

        return op();
    }
    
    @POST
    public Response op() {
        System.out.println("HELLO");
        return Response.ok("HELLO").build();
    }
}
