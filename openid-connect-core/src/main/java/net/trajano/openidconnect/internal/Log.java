package net.trajano.openidconnect.internal;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Preconfigured logger.
 *
 * @author Archimedes
 */
public class Log extends Logger {

    private static Log LOG = new Log();

    /**
     * Messages resource path.
     */
    private static final String MESSAGES = "META-INF/Messages";

    public static Log getInstance() {

        return LOG;
    }

    private Log() {

        super("net.trajano.oidc.jaspic", MESSAGES);
    }

    public void fine(final String key,
            final Object... params) {

        log(Level.FINE, key, params);
    }

}
