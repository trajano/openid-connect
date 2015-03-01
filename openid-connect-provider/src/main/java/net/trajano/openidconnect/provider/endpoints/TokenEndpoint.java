package net.trajano.openidconnect.provider.endpoints;

import java.net.URI;

import javax.ejb.EJB;
import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

import net.trajano.openidconnect.core.IdTokenResponse;
import net.trajano.openidconnect.provider.spi.BearerTokenProcessor;
import net.trajano.openidconnect.provider.spi.ClientManager;
import net.trajano.openidconnect.provider.spi.TokenProvider;

@Path("token")
public class TokenEndpoint {

    @EJB
    ClientManager cm;

    @EJB
    BearerTokenProcessor btp;

    @EJB
    TokenProvider tp;

    @GET
    public Response getOp(@QueryParam("grant_type") @NotNull GrantType grantType,
            @QueryParam("code") String code,
            @QueryParam("redirect_uri") URI redirectUri,
            @HeaderParam("Authorization") String authorization,
            @QueryParam("client_id") String clientId,
            @QueryParam("client_secret") String clientSecret,
            @Context HttpServletRequest req) {

        return op(grantType, code, redirectUri, authorization, clientId, clientSecret, req);
    }

    @POST
    public Response op(@FormParam("grant_type") @NotNull GrantType grantType,
            @FormParam("code") String code,
            @FormParam("redirect_uri") URI redirectUri,
            @HeaderParam("Authorization") String authorization,
            @FormParam("client_id") String clientId,
            @FormParam("client_secret") String clientSecret,

            @Context HttpServletRequest req) {

        System.out.println("Grant type " + grantType);

        if (authorization != null) {
            cm.authenticateClient(authorization);
        } else if (clientId != null && clientSecret != null) {
            cm.authenticateClient(clientId, clientSecret);
        } else {
            // TODO TokenErrorException
            throw new BadRequestException();
        }

        System.out.println("HELLO " + code);
        IdTokenResponse responseToken = tp.getByCode(code, true);
        System.out.println("HELLO " + responseToken);

        if (!responseToken.getIdToken()
                .getAud()
                .equals(clientId)) {
            throw new WebApplicationException();
        }
        return Response.ok(responseToken)
                .build();
    }
}
