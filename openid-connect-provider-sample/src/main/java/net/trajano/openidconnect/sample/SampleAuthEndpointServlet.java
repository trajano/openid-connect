package net.trajano.openidconnect.sample;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.trajano.openidconnect.servlet.AuthorizationEndpointServlet;
import net.trajano.openidconnect.servlet.internal.AuthenticationRequest;

@WebServlet("/oid/auth")
public class SampleAuthEndpointServlet extends AuthorizationEndpointServlet {

    @Override
    protected boolean isAuthenticated(AuthenticationRequest authenticationRequest,
            HttpServletRequest req,
            HttpServletResponse resp) throws IOException,
            ServletException {

        // TODO Auto-generated method stub
        return false;
    }

    @Override
    protected void authenticate(AuthenticationRequest authenticationRequest,
            HttpServletRequest req,
            HttpServletResponse resp) throws IOException,
            ServletException {

        // TODO Auto-generated method stub
        
    }

}
