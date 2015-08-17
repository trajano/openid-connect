package net.trajano.openidconnect.provider.endpoints;

import javax.ejb.EJB;
import javax.enterprise.context.RequestScoped;
import javax.json.JsonObject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import net.trajano.openidconnect.core.ErrorCode;
import net.trajano.openidconnect.core.ErrorResponse;
import net.trajano.openidconnect.provider.internal.AuthorizationUtil;
import net.trajano.openidconnect.provider.spi.KeyProvider;
import net.trajano.openidconnect.provider.spi.TokenProvider;
import net.trajano.openidconnect.provider.spi.UserinfoProvider;
import net.trajano.openidconnect.token.IdToken;
import net.trajano.openidconnect.token.IdTokenResponse;
import net.trajano.openidconnect.userinfo.Userinfo;

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
@RequestScoped
@Produces(MediaType.APPLICATION_JSON)
public class UserinfoEndpoint {

    @EJB
    private KeyProvider keyProvider;

    @EJB
    private TokenProvider tokenProvider;

    private UserinfoProvider userinfoProvider;

    private void filterUserInfo(final Userinfo userinfo,
        final JsonObject userinfoClaims) {

        if (!userinfoClaims.containsKey("updated_at")) {
            userinfo.setUpdatedAt(null);
        }
        if (!userinfoClaims.containsKey("email")) {
            userinfo.setEmail(null);
        }
        if (!userinfoClaims.containsKey("email_verified")) {
            userinfo.setEmailVerified(null);
        }
        if (!userinfoClaims.containsKey("name")) {
            userinfo.setName(null);
        }
        if (!userinfoClaims.containsKey("given_name")) {
            userinfo.setGivenName(null);
        }
        if (!userinfoClaims.containsKey("family_name")) {
            userinfo.setFamilyName(null);
        }
        if (!userinfoClaims.containsKey("middle_name")) {
            userinfo.setMiddleName(null);
        }
        if (!userinfoClaims.containsKey("nickname")) {
            userinfo.setNickname(null);
        }
        if (!userinfoClaims.containsKey("website")) {
            userinfo.setWebsite(null);
        }
        if (!userinfoClaims.containsKey("picture")) {
            userinfo.setPicture(null);
        }
        if (!userinfoClaims.containsKey("gender")) {
            userinfo.setGender(null);
        }
        if (!userinfoClaims.containsKey("address")) {
            userinfo.setAddress(null);
        }
        if (!userinfoClaims.containsKey("profile")) {
            userinfo.setProfile(null);
        }
        if (!userinfoClaims.containsKey("birthdate")) {
            userinfo.setBirthdate(null);
        }
        if (!userinfoClaims.containsKey("zoneinfo")) {
            userinfo.setZoneinfo(null);
        }
        if (!userinfoClaims.containsKey("locale")) {
            userinfo.setLocale(null);
        }
        if (!userinfoClaims.containsKey("preferred_username")) {
            userinfo.setPreferredUsername(null);
        }
        if (!userinfoClaims.containsKey("phone_number")) {
            userinfo.setPhoneNumber(null);
        }
        if (!userinfoClaims.containsKey("phone_number_verified")) {
            userinfo.setPhoneNumberVerified(null);
        }
    }

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
    public Response getOp(@Context final HttpServletRequest req) {

        return op(req);
    }

    @POST
    public Response op(@Context final HttpServletRequest req) {

        final String accessToken = AuthorizationUtil.processBearer(req);
        if (accessToken == null) {
            return Response.status(400)
                .entity(new ErrorResponse(ErrorCode.access_denied, "unable to retrieve id token"))
                .build();
        }
        final IdTokenResponse byAccessToken = tokenProvider.getByAccessToken(accessToken);
        if (byAccessToken == null) {
            return Response.status(400)
                .entity(new ErrorResponse(ErrorCode.access_denied, "unable to retrieve id token"))
                .build();
        }
        final IdToken idToken = byAccessToken.getIdToken(keyProvider.getPrivateJwks());
        final JsonObject claims = tokenProvider.getClaimsByAccessToken(accessToken);

        final Userinfo userinfo = userinfoProvider.getUserinfo(idToken);

        if (claims != null && claims.containsKey("userinfo")) {
            filterUserInfo(userinfo, claims.getJsonObject("userinfo"));
        }

        return Response.ok(userinfo)
            .build();
    }

    @EJB
    public void setUserinfoProvider(final UserinfoProvider userinfoProvider) {

        this.userinfoProvider = userinfoProvider;
    }

}
