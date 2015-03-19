package net.trajano.openidconnect.sample;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.trajano.openidconnect.auth.AuthenticationRequest;
import net.trajano.openidconnect.core.OpenIdConnectKey;
import net.trajano.openidconnect.provider.spi.AuthenticationResponseProvider;
import net.trajano.openidconnect.provider.spi.Authenticator;
import net.trajano.openidconnect.provider.spi.KeyProvider;

@WebServlet(urlPatterns = "/doConsent")
@Stateless
public class ConsentServlet extends HttpServlet {

    @EJB
    private KeyProvider keyProvider;

    /**
     * 
     */
    private static final long serialVersionUID = -129656605271663835L;

    @EJB
    Authenticator authenticator;

    @Override
    protected void doGet(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException {

        String requestJwt = req.getParameter(OpenIdConnectKey.REQUEST);
        try {
            AuthenticationRequest authReq = new AuthenticationRequest(requestJwt, keyProvider.getPrivateJwks());
            req.setAttribute("requestObject", authReq);
            req.getRequestDispatcher("WEB-INF/consent.jsp")
                    .forward(req, resp);
        } catch (GeneralSecurityException e) {
            throw new ServletException(e);
        }

    }

    @Override
    protected void doPost(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException {

        String subject = (String) req.getSession(false)
                .getAttribute("sub");
        
        redirector.doConsentCallback(req, resp, subject, true);
    }

    @EJB
    private AuthenticationResponseProvider redirector;

}
