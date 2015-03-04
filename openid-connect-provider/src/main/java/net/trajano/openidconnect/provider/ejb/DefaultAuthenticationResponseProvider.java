package net.trajano.openidconnect.provider.ejb;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import net.trajano.openidconnect.auth.AuthenticationRequest;
import net.trajano.openidconnect.auth.AuthenticationResponse;
import net.trajano.openidconnect.auth.ResponseMode;
import net.trajano.openidconnect.auth.ResponseType;
import net.trajano.openidconnect.provider.internal.AuthenticationResponseConverter;
import net.trajano.openidconnect.provider.internal.CacheConstants;
import net.trajano.openidconnect.provider.spi.AuthenticationResponseProvider;
import net.trajano.openidconnect.provider.spi.TokenProvider;
import net.trajano.openidconnect.token.IdToken;
import net.trajano.openidconnect.token.IdTokenResponse;
import net.trajano.openidconnect.token.TokenResponse;

/**
 * Upon successful authentication, implementers are expected to invoke any of
 * the methods below. This class is meant to be injected into a servlet or REST
 * service. ?? should I move this and perhaps key provider into a EJB jar.
 *
 * @author Archimedes Trajano
 */
@Stateless
public class DefaultAuthenticationResponseProvider implements AuthenticationResponseProvider {

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
            final String subject) throws IOException,
            GeneralSecurityException {

        final AuthenticationResponse response = new AuthenticationResponse();

        final IdToken idToken = tokenProvider.buildIdToken(subject, request);
        final String code = tokenProvider.store(idToken, request);

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
        return response;
    }

    /**
     * Builds a JAX-RS {@link Response} object containing a redirect
     *
     * @param responseType
     * @param subject
     * @param state
     * @param redirectUri
     * @param extraStorageOptions
     * @return
     */
    @Override
    public Response buildResponse(final AuthenticationRequest request,
            final String subject) {

        final AuthenticationResponse response;
        try {
            response = buildAuthenticationResponse(request, subject);
        } catch (IOException | GeneralSecurityException e) {
            throw new WebApplicationException(e);
        }
        final AuthenticationResponseConverter converter = new AuthenticationResponseConverter(request.getRedirectUri(), response);
        if (request.getResponseMode() == ResponseMode.query) {
            return Response.temporaryRedirect(converter.toQueryUri())
                    .build();
        } else if (request.getResponseMode() == ResponseMode.form_post) {

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
    public void doCallback(final HttpServletResponse response,
            final AuthenticationRequest request,
            final String subject) throws IOException,
            ServletException {

        try {
            final AuthenticationResponseConverter authenticationResponse = new AuthenticationResponseConverter(request.getRedirectUri(), buildAuthenticationResponse(request, subject));
            if (request.getResponseMode() == ResponseMode.query) {
                response.sendRedirect(authenticationResponse.toQueryUri()
                        .toASCIIString());

            } else if (request.getResponseMode() == ResponseMode.form_post) {
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
    public void setTokenProvider(final TokenProvider tokenProvider) {

        this.tokenProvider = tokenProvider;
    }
}
