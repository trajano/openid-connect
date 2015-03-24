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
import net.trajano.openidconnect.crypto.Encoding;

// TODO get rid of this use the same strat as /logout
@WebServlet(urlPatterns = "/doLogin")
@Stateless
public class LoginServlet extends HttpServlet {

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

        String subject = Encoding.base64urlEncode(req.getParameter("username"));
        req.getSession()
                .setAttribute("sub", subject);

        redirector.doCallback(req, resp, subject);
    }

    @EJB
    private AuthenticationResponseProvider redirector;

}
