package net.trajano.openidconnect.provider.internal;

import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.BadRequestException;

import net.trajano.openidconnect.core.TokenResponse;
import net.trajano.openidconnect.crypto.Base64Url;
import net.trajano.openidconnect.provider.BearerTokenException;
import net.trajano.openidconnect.provider.ClientManager;
import net.trajano.openidconnect.provider.TokenProvider;

@Stateless
public class BearerTokenProcessor {

    /**
     * Used to authenticate after processing
     */
    private ClientManager clientManager;

    private TokenProvider idtokenProvider;

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
    public String validateAndGetClientId(final HttpServletRequest request) {

        final String s = Base64Url.decodeToString(getEncodedToken(request));
        final String clientId = s.substring(0, s.indexOf(':'));
        final String clientSecret = s.substring(s.indexOf(':') + 1);
        if (!clientManager.authenticateClient(clientId, clientSecret)) {
            throw new BearerTokenException(clientManager, "invalid_token");
        }
        return clientId;

    }

    private String getEncodedToken(HttpServletRequest request) {

        if (!request.isSecure()) {
            throw new BadRequestException();
        }

        final String authorization = request.getHeader("Authorization");
        if (authorization == null) {
            throw new BearerTokenException(clientManager);
        }
        final String[] authorizationComponents = authorization.split(" ");
        if (!"Bearer".equals(authorizationComponents[0])) {
            throw new BearerTokenException(clientManager);
        }
        return authorizationComponents[1];

    }

    public TokenResponse getToken(HttpServletRequest request) {

        final String accessToken = getEncodedToken(request);
        return idtokenProvider.getByAccessToken(accessToken);
    }
}
