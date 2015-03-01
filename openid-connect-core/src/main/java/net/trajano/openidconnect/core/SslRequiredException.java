package net.trajano.openidconnect.core;

/**
 * This is a helper for the common check to ensure SSL is present
 * 
 * @author Archimedes
 */
public class SslRequiredException extends OAuthException {

    public SslRequiredException() {

        super(Error.invalid_request, "SSL required");
    }
}
