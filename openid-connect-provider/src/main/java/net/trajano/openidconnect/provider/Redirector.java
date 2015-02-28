package net.trajano.openidconnect.provider;

import java.io.IOException;
import java.net.URI;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.core.IdToken;

@Stateless
public class Redirector {

    private IdTokenProvider tokenProvider;

    /**
     * @param responseType
     *            response_type value
     */
    public void doSomethinglikestoringthetokensoitcanberetrievedlater(String responseType,
            IdToken idToken) {

        if ("code".equals(responseType)) {
            // store the token in the token provider and get a code to retrieve the token
        }
    }

    public void authorizationCodeRedirect(URI redirectUri,
            String code,
            String state,
            HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException {

        UriBuilder b = UriBuilder.fromUri(redirectUri)
                .queryParam("code", code);
        if (state != null) {
            b.queryParam("state", state);
        }
        resp.sendRedirect(b.build()
                .toASCIIString());

    }

    @EJB
    public void setTokenProvider(IdTokenProvider tokenProvider) {

        this.tokenProvider = tokenProvider;
    }
}
