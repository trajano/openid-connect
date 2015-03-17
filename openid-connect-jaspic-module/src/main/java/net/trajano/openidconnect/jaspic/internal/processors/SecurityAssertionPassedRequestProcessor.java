package net.trajano.openidconnect.jaspic.internal.processors;

import java.io.IOException;

import javax.security.auth.message.AuthStatus;

import net.trajano.openidconnect.jaspic.internal.ValidateContext;
import net.trajano.openidconnect.jaspic.internal.ValidateRequestProcessor;

/**
 * Processes any requests that would pass the security assertions.
 * 
 * @author Archimedes
 */
public class SecurityAssertionPassedRequestProcessor implements ValidateRequestProcessor {

    @Override
    public boolean canValidateRequest(final ValidateContext context) {

        if (!context.isMandatory() && !context.isSecure()) {
            return true;
        }
        if (!context.isMandatory() || context.hasTokenCookie() && !context.getTokenCookie()
                .isExpired()) {
            return true;
        }
        return false;
    }

    @Override
    public AuthStatus validateRequest(final ValidateContext context) throws IOException {

        return AuthStatus.SUCCESS;
    }
}
