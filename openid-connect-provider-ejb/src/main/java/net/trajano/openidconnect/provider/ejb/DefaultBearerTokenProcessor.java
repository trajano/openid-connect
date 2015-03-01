package net.trajano.openidconnect.provider.ejb;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.BadRequestException;

import net.trajano.openidconnect.core.IdTokenResponse;
import net.trajano.openidconnect.crypto.Base64Url;
import net.trajano.openidconnect.provider.spi.BearerTokenException;
import net.trajano.openidconnect.provider.spi.BearerTokenProcessor;
import net.trajano.openidconnect.provider.spi.ClientManager;
import net.trajano.openidconnect.provider.spi.TokenProvider;

@Stateless
public class DefaultBearerTokenProcessor implements BearerTokenProcessor {

    /**
     * Used to authenticate after processing
     */
    private ClientManager clientManager;

    @EJB
    public void setIdtokenProvider(TokenProvider idtokenProvider) {

        this.idtokenProvider = idtokenProvider;
    }

    private TokenProvider idtokenProvider;

    @EJB
    public void setClientManager(final ClientManager clientManager) {

        this.clientManager = clientManager;
    }

    /**
     * Validates the Authorization header value to ensure that the client ID
     * matches the secret and extracts the client ID. It also ensures that we
     * are using SSL.
     *
     * @param request
     *            servlet request
     * @throws BadRequestException
     *             if the connection is not secure
     * @throws BearerTokenException
     *             if there is any problem
     * @return client ID.
     */
    @Override
    public String validateAndGetClientId(final HttpServletRequest request) {

        final String clientId;
        final String clientSecret;
        if (request.getParameter("client_id") != null && request.getParameter("client_secret") != null) {
            clientId = request.getParameter("client_id");
            clientSecret = request.getParameter("client_secret");
        } else {
            final String s = Base64Url.decodeToString(getEncodedToken(request, "Basic"));
            clientId = s.substring(0, s.indexOf(':'));
            clientSecret = s.substring(s.indexOf(':') + 1);
        }
        if (!clientManager.authenticateClient(clientId, clientSecret)) {
            throw new BearerTokenException(clientManager, "invalid_token");
        }
        return clientId;

    }

    private String getEncodedToken(HttpServletRequest request,
            String type) {

        if (!request.isSecure()) {
            throw new BadRequestException();
        }

        final String authorization = request.getHeader("Authorization");
        System.out.println("Authorization: " + authorization);
        if (authorization == null) {
            throw new BearerTokenException(clientManager);
        }
        final String[] authorizationComponents = authorization.split(" ");
        if (!type.equals(authorizationComponents[0])) {
            throw new BearerTokenException(clientManager);
        }
        return authorizationComponents[1];

    }

    @Override
    public IdTokenResponse getToken(HttpServletRequest request) {

        final String accessToken = getEncodedToken(request, "Bearer");
        return idtokenProvider.getByAccessToken(accessToken);
    }
}
