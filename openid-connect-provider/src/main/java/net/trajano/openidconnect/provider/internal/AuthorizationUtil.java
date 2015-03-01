package net.trajano.openidconnect.provider.internal;

import javax.servlet.http.HttpServletRequest;

import net.trajano.openidconnect.core.InvalidClientException;
import net.trajano.openidconnect.core.SslRequiredException;
import net.trajano.openidconnect.crypto.Base64Url;

/**
 * Helper class to manage the Authorization tag
 * 
 * @author Archimedes
 */
public final class AuthorizationUtil {

    public static ClientCredentials processBasicOrQuery(HttpServletRequest req) {

        if (!req.isSecure()) {
            throw new SslRequiredException();
        }

        if (req.getHeader("Authorization") != null) {
            String basicCredentials = getDecodedValue(req, "Basic");
            String[] credentials = basicCredentials.split(":");
            if (credentials.length != 2) {
                throw new InvalidClientException();
            }
            return new ClientCredentials(credentials[0], credentials[1]);
        } else if (req.getParameter("client_id") != null && req.getParameter("client_secret") != null) {
            return new ClientCredentials(req.getParameter("client_id"), req.getParameter("client_secret"));
        } else {
            throw new InvalidClientException();
        }
    }

    public static String processBearer(HttpServletRequest req) {

        if (!req.isSecure()) {
            throw new SslRequiredException();
        }

        if (req.getHeader("Authorization") != null) {
            return getDecodedValue(req, "Bearer");
        } else {
            throw new InvalidClientException();
        }
    }

    private static String getDecodedValue(HttpServletRequest request,
            String type) {

        final String authorization = request.getHeader("Authorization");
        if (authorization == null) {
            throw new InvalidClientException();
        }
        final String[] authorizationComponents = authorization.split("\\s+");
        if (authorizationComponents.length != 2)
            throw new InvalidClientException();

        if (!type.equals(authorizationComponents[0])) {
            throw new InvalidClientException();
        }

        return Base64Url.decodeToString(authorizationComponents[1]);

    }

    private AuthorizationUtil() {

    }
}
