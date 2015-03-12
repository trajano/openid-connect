package net.trajano.openidconnect.provider.ejb;

import static java.net.URI.create;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.auth.AuthenticationRequest;
import net.trajano.openidconnect.auth.AuthenticationResponse;
import net.trajano.openidconnect.auth.ResponseMode;
import net.trajano.openidconnect.auth.ResponseType;
import net.trajano.openidconnect.provider.internal.AuthenticationResponseConverter;
import net.trajano.openidconnect.provider.internal.CacheConstants;
import net.trajano.openidconnect.provider.spi.AuthenticationResponseProvider;
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
            final String subject) {

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

        try {
            final AuthenticationRequest request = new AuthenticationRequest(req, keyProvider.getPrivateJwks());
            final AuthenticationResponse authResponse = buildAuthenticationResponse(request, req, subject);
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

    @EJB
    public void setKeyProvider(final KeyProvider keyProvider) {

        this.keyProvider = keyProvider;
    }

    @EJB
    public void setTokenProvider(final TokenProvider tokenProvider) {

        this.tokenProvider = tokenProvider;
    }
}
