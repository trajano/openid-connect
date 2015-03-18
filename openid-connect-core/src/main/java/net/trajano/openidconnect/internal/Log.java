package net.trajano.openidconnect.internal;

import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Preconfigured logger.
 *
 * @author Archimedes
 */
public class Log {

    private static final Logger LOG;

    /**
     * Messages resource path.
     */
    private static final String MESSAGES = "META-INF/Messages";

    private static final ResourceBundle R = ResourceBundle.getBundle(MESSAGES);

    static {
        LOG = Logger.getLogger("net.trajano.oidc.core", MESSAGES);
    }

    public static void fine(final String key,
            final Object... params) {

        LOG.log(Level.FINE, key, params);
    }

    public static Logger getInstance() {

        return LOG;
    }

    public static String r(final String key) {

        return R.getString(key);
    }

}
