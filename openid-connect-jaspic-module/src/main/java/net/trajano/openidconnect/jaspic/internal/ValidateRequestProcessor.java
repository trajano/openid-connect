package net.trajano.openidconnect.jaspic.internal;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.security.auth.message.AuthStatus;

public interface ValidateRequestProcessor {

    boolean canValidateRequest(ValidateContext context);

    AuthStatus validateRequest(ValidateContext context) throws IOException, GeneralSecurityException;
}
