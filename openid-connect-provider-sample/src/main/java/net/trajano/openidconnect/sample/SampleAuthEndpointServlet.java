package net.trajano.openidconnect.sample;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.trajano.openidconnect.servlet.AuthorizationEndpointServlet;
import net.trajano.openidconnect.servlet.ClientManager;
import net.trajano.openidconnect.servlet.internal.AuthenticationRequest;

import org.apache.shiro.SecurityUtils;

@WebServlet("/oid/auth")
public class SampleAuthEndpointServlet extends AuthorizationEndpointServlet {

    @Override
    protected boolean isAuthenticated(AuthenticationRequest authenticationRequest,
            HttpServletRequest req,
            HttpServletResponse resp) throws IOException,
            ServletException {

        return SecurityUtils.getSubject()
                .isAuthenticated();
    }

    @Override
    protected void authenticate(AuthenticationRequest authenticationRequest,
            HttpServletRequest req,
            HttpServletResponse resp) throws IOException,
            ServletException {

        resp.sendRedirect(req.getContextPath() + "/login.jsp");

    }

    @Override
    protected ClientManager buildClientManager() throws ServletException {

        return new AcceptAllClientManager();
    }

}
