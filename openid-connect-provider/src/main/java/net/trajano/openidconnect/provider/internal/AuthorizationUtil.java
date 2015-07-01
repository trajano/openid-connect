package net.trajano.openidconnect.provider.internal;

import javax.servlet.http.HttpServletRequest;

import net.trajano.openidconnect.crypto.Encoding;
import net.trajano.openidconnect.token.InvalidClientException;

/**
 * Helper class to manage the Authorization tag
 *
 * @author Archimedes
 */
public final class AuthorizationUtil {

    private static final String BASIC_AUTHORIZATION = "Basic";

    private static final String BEARER_AUTHORIZATION = "Bearer";

    private static String getValue(final HttpServletRequest request,
            final String type) {

        final String authorization = request.getHeader("Authorization");
        if (authorization == null) {
            throw new InvalidClientException(type);
        }
        final String[] authorizationComponents = authorization.split("\\s+");
        if (authorizationComponents.length != 2) {
            throw new InvalidClientException(type);
        }

        if (!type.equals(authorizationComponents[0])) {
            throw new InvalidClientException(type);
        }

        return authorizationComponents[1];

    }

    public static ClientCredentials processBasicOrQuery(final HttpServletRequest req) {

        if (req.getHeader("Authorization") != null) {
            final String basicCredentials = Encoding.base64urlDecodeToString(getValue(req, BASIC_AUTHORIZATION));
            final String[] credentials = basicCredentials.split(":");
            if (credentials.length != 2) {
                throw new InvalidClientException(BASIC_AUTHORIZATION);
            }
            return new ClientCredentials(credentials[0], credentials[1]);
        } else if (req.getParameter("client_id") != null && req.getParameter("client_secret") != null) {
            return new ClientCredentials(req.getParameter("client_id"), req.getParameter("client_secret"));
        } else {
            throw new InvalidClientException(BASIC_AUTHORIZATION);
        }
    }

    /**
     * Checks for the <code>Authorization</code> header first.  If it does not find it, it will try to get it from the body.
     * @param req
     * @return
     */
    public static String processBearer(final HttpServletRequest req) {

        if (req.getHeader("Authorization") != null) {
            return getValue(req, BEARER_AUTHORIZATION);
        } else {
            return req.getParameter("access_token");
        }
    }

    private AuthorizationUtil() {

    }
}
