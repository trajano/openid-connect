package net.trajano.openidconnect.jaspic.internal;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Map;

import javax.json.JsonObject;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.client.Client;

import net.trajano.openidconnect.crypto.JsonWebTokenProcessor;

public class ValidateContext {

    private final Client client;

    private final Subject clientSubject;

    private final boolean mandatory;

    private final Map<String, String> options;

    private final HttpServletRequest req;

    private final HttpServletResponse resp;

    private final TokenCookie tokenCookie;

    public ValidateContext(final Client client, final Subject clientSubject, final boolean mandatory, final Map<String, String> options, final HttpServletRequest req, final HttpServletResponse resp, final TokenCookie tokenCookie) {

        this.client = client;
        this.clientSubject = clientSubject;
        this.mandatory = mandatory;
        this.options = options;
        this.req = req;
        this.resp = resp;
        this.tokenCookie = tokenCookie;
    }

    public Client getClient() {

        return client;
    }

    public Subject getClientSubject() {

        return clientSubject;
    }

    /**
     * Gets the id_token from the cookie. It will perform the JWT processing
     * needed.
     * 
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public JsonObject getIdToken() throws IOException,
            GeneralSecurityException {

        return new JsonWebTokenProcessor(tokenCookie.getIdTokenJwt()).signatureCheck(false)
                .getJsonPayload();
    }

    public Map<String, String> getOptions() {

        return options;
    }

    public HttpServletRequest getReq() {

        return req;
    }

    public HttpServletResponse getResp() {

        return resp;
    }

    public TokenCookie getTokenCookie() {

        return tokenCookie;
    }

    public boolean hasTokenCookie() {

        return tokenCookie != null;
    }

    /**
     * Checks if the request uses the GET method.
     *
     * @param req
     *            request
     * @return <code>true</code> if the request uses the GET method.
     */
    public boolean isGetRequest() {

        return "GET".equals(req.getMethod());

    }

    public boolean isMandatory() {

        return mandatory;
    }

    /**
     * Checks if the request URI matches the option value for the key provided.
     *
     * @param key
     *            option key
     * @return
     */
    public boolean isRequestUri(final String key) {

        return req.getRequestURI()
                .equals(options.get(key));
    }

    public boolean isSecure() {

        return req.isSecure();
    }

    public void setContentType(final String contentType) {

        resp.setContentType(contentType);

    }

}
