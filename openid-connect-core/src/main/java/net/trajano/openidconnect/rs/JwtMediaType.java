package net.trajano.openidconnect.rs;

import javax.ws.rs.core.MediaType;

/**
 * Adds JWT media types.
 * 
 * @author Archimedes
 */
public class JwtMediaType extends MediaType {

    public static final String APPLICATION_JWT = "application/jwt";

    public static final MediaType APPLICATION_JWT_TYPE = new MediaType("application", "jwt");
}
