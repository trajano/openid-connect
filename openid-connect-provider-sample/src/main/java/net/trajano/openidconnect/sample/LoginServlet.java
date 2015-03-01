package net.trajano.openidconnect.sample;

import java.io.IOException;

import javax.ejb.EJB;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.trajano.openidconnect.provider.AuthenticationRequest;
import net.trajano.openidconnect.provider.spi.AuthenticationRedirector;

@WebServlet(urlPatterns = "/doLogin", loadOnStartup = 1)
public class LoginServlet extends HttpServlet {

    /**
     * 
     */
    private static final long serialVersionUID = -1296536605271663835L;

    @Override
    protected void doPost(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException {

        String subject = req.getParameter("username");
        System.out.println("got subject " + subject);
        redirector.performRedirect(resp, new AuthenticationRequest(req), subject);
    }

    @EJB
    AuthenticationRedirector redirector;
}
