package net.trajano.openidconnect.servlet;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

import javax.servlet.ServletException;
import javax.servlet.ServletRegistration;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OpenIdConfigurationServlet extends HttpServlet {
	/**
	 * Determines the endpoints for OAuth2 based on the mappings specified in
	 * the {@link ServletRegistration}s.
	 */
	@Override
	public void init() throws ServletException {
		for (ServletRegistration servletRegistration : getServletContext()
				.getServletRegistrations().values()) {
			servletRegistration.getClassName();
			Iterator<String> iterator = servletRegistration.getMappings()
					.iterator();
			String mapping = iterator.next();
			if (iterator.hasNext()) {
				throw new ServletException("more than one mapping");
			} else if (!mapping.startsWith("/")) {
				throw new ServletException(
						"mapping is expected to start with /");
			}
		}

	}

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		super.doGet(req, resp);
	}
}
