package net.trajano.openidconnect.sample;

import java.io.IOException;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.trajano.openidconnect.provider.spi.AuthenticationResponseProvider;
import net.trajano.openidconnect.provider.spi.Authenticator;

@WebServlet(urlPatterns = "/doConsent")
@Stateless
public class ConsentServlet extends HttpServlet {

    /**
     * 
     */
    private static final long serialVersionUID = -129656605271663835L;

    @EJB
    Authenticator authenticator;

    @Override
    protected void doPost(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException {

        String subject = (String) req.getSession()
                .getAttribute("sub");

        redirector.doCallback(req, resp, subject, true);
    }

    @EJB
    private AuthenticationResponseProvider redirector;

}
