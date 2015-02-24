package net.trajano.openidconnect.sample;

import javax.servlet.annotation.WebServlet;

import net.trajano.openidconnect.servlet.AuthorizationEndpointServlet;

@WebServlet("/oid/auth")
public class SampleAuthEndpointServlet extends AuthorizationEndpointServlet {

}
