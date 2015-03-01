package net.trajano.openidconnect.provider.internal;

import java.io.IOException;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.trajano.openidconnect.provider.ejb.AcceptAllClientManager;
import net.trajano.openidconnect.provider.spi.AuthenticationRedirector;
import net.trajano.openidconnect.provider.spi.AuthenticationRequest;

@WebServlet(urlPatterns = "/doLogin2", loadOnStartup = 1)
@Stateless
public class LoginServlet extends HttpServlet {

    /**
     * 
     */
    private static final long serialVersionUID = -1296536605271663835L;

    @Override
    protected void doGet(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException {

        resp.getWriter()
                .print("RR" + redirector);
        resp.getWriter()
                .print("RR" + acm);

    }

    @Override
    protected void doPost(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException {

        String subject = req.getParameter("username");
        System.out.println("got subject " + subject);
        redirector.performRedirect(resp, new AuthenticationRequest(req), subject);
    }

    
    AcceptAllClientManager acm;

    @EJB
    private AuthenticationRedirector redirector;
}
