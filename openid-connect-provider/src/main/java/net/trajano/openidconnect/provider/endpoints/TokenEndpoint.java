package net.trajano.openidconnect.provider.endpoints;

import java.net.URI;

import javax.ejb.EJB;
import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import net.trajano.openidconnect.core.GrantType;
import net.trajano.openidconnect.core.IdTokenResponse;
import net.trajano.openidconnect.provider.internal.AuthorizationUtil;
import net.trajano.openidconnect.provider.internal.ClientCredentials;
import net.trajano.openidconnect.provider.spi.ClientManager;
import net.trajano.openidconnect.provider.spi.TokenProvider;

@Path("token")
@Produces(MediaType.APPLICATION_JSON)
public class TokenEndpoint {

    @EJB
    ClientManager cm;

    @EJB
    TokenProvider tp;

    @GET
    public Response getOp(@QueryParam("grant_type") @NotNull final GrantType grantType,
            @QueryParam("code") final String code,
            @QueryParam("redirect_uri") final URI redirectUri,
            @Context final HttpServletRequest req) {

        return op(grantType, code, redirectUri, req);
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response op(@FormParam("grant_type") @NotNull final GrantType grantType,
            @FormParam("code") final String code,
            @FormParam("redirect_uri") final URI redirectUri,
            @Context final HttpServletRequest req) {

        final ClientCredentials cred = AuthorizationUtil.processBasicOrQuery(req);

        final IdTokenResponse responseToken = tp.getByCode(code, true);

        if (!responseToken.getIdToken()
                .getAud()
                .equals(cred.getClientId())) {
            throw new WebApplicationException();
        }
        return Response.ok(responseToken)
                .build();
    }
}
