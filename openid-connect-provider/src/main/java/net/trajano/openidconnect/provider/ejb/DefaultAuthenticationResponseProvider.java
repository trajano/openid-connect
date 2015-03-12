package net.trajano.openidconnect.provider.ejb;

import static java.net.URI.create;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.auth.AuthenticationRequest;
import net.trajano.openidconnect.auth.AuthenticationResponse;
import net.trajano.openidconnect.auth.ResponseMode;
import net.trajano.openidconnect.auth.ResponseType;
import net.trajano.openidconnect.core.OpenIdConnectKey;
import net.trajano.openidconnect.provider.internal.AuthenticationResponseConverter;
import net.trajano.openidconnect.provider.internal.CacheConstants;
import net.trajano.openidconnect.provider.spi.AuthenticationResponseProvider;
import net.trajano.openidconnect.provider.spi.Authenticator;
import net.trajano.openidconnect.provider.spi.ClientManager;
import net.trajano.openidconnect.provider.spi.Consent;
import net.trajano.openidconnect.provider.spi.KeyProvider;
import net.trajano.openidconnect.provider.spi.TokenProvider;
import net.trajano.openidconnect.token.IdTokenResponse;
import net.trajano.openidconnect.token.TokenResponse;

/**
 * Upon successful authentication, implementers are expected to invoke any of
 * the methods below. This class is meant to be injected into a servlet or REST
 * service.
 *
 * @author Archimedes Trajano
 */
@Stateless
public class DefaultAuthenticationResponseProvider implements AuthenticationResponseProvider {

    private KeyProvider keyProvider;

    private TokenProvider tokenProvider;

    @EJB
    private Authenticator authenticator;

    @EJB
    private ClientManager clientManager;

    /**
     * @param responseType
     *            response_type value
     * @param subject
     *            subject
     * @param state
     *            state
     * @param redirectUri
     *            redirect URI.
     * @param extraOptions
     *            extra options for building the idtoken
     * @throws GeneralSecurityException
     * @throws IOException
     */
    @Override
    public AuthenticationResponse buildAuthenticationResponse(final AuthenticationRequest request,
            final HttpServletRequest req,
            final String subject) throws IOException,
            GeneralSecurityException {

        final AuthenticationResponse response = new AuthenticationResponse();

        final UriBuilder issuerUri = UriBuilder.fromUri(create(req.getRequestURL()
                .toString()))
                .scheme("https")
                .replacePath(req.getContextPath())
                .replaceQuery(null)
                .fragment(null);

        final String code = tokenProvider.createNewToken(subject, issuerUri.build(), request);

        if (request.getState() != null) {
            response.setState(request.getState());
        }

        final boolean implicitFlow = request.isImplicitFlow();
        final IdTokenResponse tokenResponse = tokenProvider.getByCode(code, implicitFlow);
        if (request.containsResponseType(ResponseType.id_token)) {
            response.setEncodedIdToken(tokenResponse.getEncodedIdToken());
        }
        if (request.containsResponseType(ResponseType.token)) {
            response.setAccessToken(TokenResponse.BEARER, tokenResponse.getAccessToken());
        }
        if (request.containsResponseType(ResponseType.code)) {
            response.setCode(code);
        }
        response.setRedirectUri(request.getRedirectUri());
        response.setResponseMode(request.getResponseMode());
        return response;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Response buildResponse(final String requestJwt,
            final HttpServletRequest request,
            final String subject) {

        try {
            final AuthenticationRequest req = new AuthenticationRequest(requestJwt, keyProvider.getPrivateJwks());
            return buildResponse(req, request, subject);
        } catch (IOException | GeneralSecurityException e) {
            throw new WebApplicationException(e);
        }

    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Response buildResponse(final AuthenticationRequest req,
            final HttpServletRequest request,
            final String subject,
            boolean consent) {

        final AuthenticationResponse response;
        try {
            response = buildAuthenticationResponse(req, request, subject);
        } catch (IOException | GeneralSecurityException e) {
            throw new WebApplicationException(e);
        }
        final AuthenticationResponseConverter converter = new AuthenticationResponseConverter(response.getRedirectUri(), response);
        if (response.getResponseMode() == ResponseMode.query) {
            return Response.temporaryRedirect(converter.toQueryUri())
                    .build();
        } else if (response.getResponseMode() == ResponseMode.form_post) {

            return Response.ok(converter.toFormPost())
                    .type(MediaType.TEXT_HTML_TYPE)
                    .cacheControl(CacheConstants.NO_CACHE)
                    .build();
        } else {
            return Response.temporaryRedirect(converter.toFragmentUri())
                    .build();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Response buildResponse(final AuthenticationRequest req,
            final HttpServletRequest request,
            final String subject) {

        return buildResponse(req, request, subject, false);
    }

    /**
     * Calls for the authentication callback. Perform a redirect with the
     * authorization response data.
     *
     * @param response
     * @param responseType
     * @param subject
     * @param state
     * @param redirectUri
     * @param extraStorageOptions
     * @throws IOException
     */
    @Override
    public void doCallback(final HttpServletRequest req,
            final HttpServletResponse response,
            final String subject) throws IOException,
            ServletException {

        doCallback(req, response, subject, false);

    }

    /**
     * Gets the consent URI assuming the user has not consented yet.
     * 
     * @param requestJwt
     * @param authReq
     * @param req
     * @param subject
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    private URI getConsentRequestUri(String requestJwt,
            AuthenticationRequest authReq,
            HttpServletRequest req,
            String subject) throws IOException,
            GeneralSecurityException {

        Consent consentRequested = new Consent(authenticator.getSubject(req), authReq.getClientId(), authReq.getScopes());

        if (tokenProvider.getByConsent(consentRequested) == null) {
            final UriBuilder contextUriBuilder = UriBuilder.fromUri(req.getRequestURL()
                    .toString())
                    .replacePath(req.getContextPath());

            return authenticator.consent(authReq, requestJwt, req, contextUriBuilder);
        }
        return null;
    }

    @EJB
    public void setKeyProvider(final KeyProvider keyProvider) {

        this.keyProvider = keyProvider;
    }

    @EJB
    public void setTokenProvider(final TokenProvider tokenProvider) {

        this.tokenProvider = tokenProvider;
    }

    @Context
    javax.ws.rs.ext.Providers providers;

    @Override
    public Response buildResponse(String requestJwt,
            HttpServletRequest request,
            String subject,
            boolean consent) {

        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void doCallback(HttpServletRequest req,
            HttpServletResponse response,
            String subject,
            boolean consent) throws IOException,
            ServletException {

        String requestJwt = req.getParameter(OpenIdConnectKey.REQUEST);
        try {
            final AuthenticationRequest authReq = new AuthenticationRequest(requestJwt, keyProvider.getPrivateJwks());

            if (!consent) {
                URI consentRequestURI = getConsentRequestUri(requestJwt, authReq, req, subject);
                if (consentRequestURI != null) {
                    response.sendRedirect(consentRequestURI.toASCIIString());
                    return;
                }
            }
            final AuthenticationResponse authResponse = buildAuthenticationResponse(authReq, req, subject);
            final AuthenticationResponseConverter authenticationResponse = new AuthenticationResponseConverter(authResponse.getRedirectUri(), authResponse);
            if (authResponse.getResponseMode() == ResponseMode.query) {
                response.sendRedirect(authenticationResponse.toQueryUri()
                        .toASCIIString());

            } else if (authResponse.getResponseMode() == ResponseMode.form_post) {
                final String formPost = authenticationResponse.toFormPost();
                response.setContentLength(formPost.length());
                response.getWriter()
                        .print(formPost);
            } else {
                response.sendRedirect(authenticationResponse.toFragmentUri()
                        .toASCIIString());
            }
        } catch (final GeneralSecurityException e) {
            throw new ServletException(e);
        }

    }

}
