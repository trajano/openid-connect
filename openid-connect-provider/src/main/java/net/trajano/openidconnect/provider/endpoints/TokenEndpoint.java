package net.trajano.openidconnect.provider.endpoints;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;

import javax.ejb.EJB;
import javax.enterprise.context.RequestScoped;
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
import javax.ws.rs.core.Response.Status;

import net.trajano.openidconnect.core.ErrorCode;
import net.trajano.openidconnect.core.ErrorResponse;
import net.trajano.openidconnect.core.OpenIdConnectException;
import net.trajano.openidconnect.provider.internal.AuthorizationUtil;
import net.trajano.openidconnect.provider.internal.ClientCredentials;
import net.trajano.openidconnect.provider.spi.ClientManager;
import net.trajano.openidconnect.provider.spi.KeyProvider;
import net.trajano.openidconnect.provider.spi.TokenProvider;
import net.trajano.openidconnect.token.GrantType;
import net.trajano.openidconnect.token.IdTokenResponse;
import net.trajano.openidconnect.token.TokenResponse;

@Path("token")
@RequestScoped
@Produces(MediaType.APPLICATION_JSON)
public class TokenEndpoint {

    @EJB
    private ClientManager cm;

    @EJB
    private KeyProvider kp;

    @EJB
    private TokenProvider tp;

    @GET
    public Response getOp(@QueryParam("grant_type") @NotNull final GrantType grantType,
        @QueryParam("code") final String code,
        @QueryParam("refresh_token") final String refreshToken,
        @QueryParam("redirect_uri") final URI redirectUri,
        @Context final HttpServletRequest req) throws IOException,
            GeneralSecurityException {

        return op(grantType, code, refreshToken, redirectUri, req);
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response op(@FormParam("grant_type") @NotNull final GrantType grantType,
        @FormParam("code") final String code,
        @FormParam("refresh_token") final String refreshToken,
        @FormParam("redirect_uri") final URI redirectUri,
        @Context final HttpServletRequest req) throws IOException,
            GeneralSecurityException {

        final ClientCredentials cred = AuthorizationUtil.processBasicOrQuery(req);

        if (grantType == GrantType.authorization_code) {
            final IdTokenResponse responseToken = tp.getByCode(code, true);
            if (responseToken == null) {
                return Response.ok(new ErrorResponse(ErrorCode.access_denied, "unable to obtain response token"))
                    .status(Status.BAD_REQUEST)
                    .build();
            }
            if (!responseToken.getIdToken(kp.getJwks())
                .getAud()
                .equals(cred.getClientId())) {
                throw new WebApplicationException();
            }
            return Response.ok(responseToken)
                .build();
        } else if (grantType == GrantType.refresh_token) {
            final TokenResponse responseToken = tp.refreshToken(cred.getClientId(), refreshToken, null, null);
            return Response.ok(responseToken)
                .build();
        } else {
            throw new OpenIdConnectException(ErrorCode.invalid_grant);
        }

    }
}
