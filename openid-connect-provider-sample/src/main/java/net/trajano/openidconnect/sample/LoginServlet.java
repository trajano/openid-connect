package net.trajano.openidconnect.sample;

import java.io.IOException;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;

import net.trajano.openidconnect.provider.spi.AuthenticationRedirector;
import net.trajano.openidconnect.provider.spi.AuthenticationRequest;
import net.trajano.openidconnect.provider.spi.KeyProvider;
import net.trajano.openidconnect.provider.spi.TokenProvider;

@WebServlet(urlPatterns = "/doLogin")
@Stateless
public class LoginServlet extends HttpServlet {

    /**
     * 
     */
    private static final long serialVersionUID = -129656605271663835L;

    @Override
    protected void doGet(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException {

        resp.setContentType(MediaType.TEXT_PLAIN);
        resp.getWriter()
                .print(kp);
        resp.getWriter()
                .print(tp);

        resp.getWriter()
                .println();
        resp.getWriter()
                .println(tp.getAllTokenResponses());

    }

    @Override
    protected void doPost(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException {

        String subject = req.getParameter("username");
        System.out.println("got subject " + subject);
        redirector.performRedirect(resp, new AuthenticationRequest(req), subject);
    }

    @EJB
    private AuthenticationRedirector redirector;

    @EJB
    private KeyProvider kp;

    @EJB
    private TokenProvider tp;
}
