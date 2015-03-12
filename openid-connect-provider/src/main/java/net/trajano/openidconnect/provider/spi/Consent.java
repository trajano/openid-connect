package net.trajano.openidconnect.provider.spi;

import java.io.Serializable;
import java.util.Objects;
import java.util.Set;

import javax.xml.bind.annotation.XmlRootElement;

import net.trajano.openidconnect.core.Scope;
import net.trajano.openidconnect.token.IdToken;
import net.trajano.openidconnect.token.IdTokenResponse;

/**
 * A {@link TokenStorage} lookup key containing the subject and client id.
 *
 * @author Archimedes
 */
@XmlRootElement
public class Consent implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -7366727338405104035L;

    private final String clientId;

    private final Set<Scope> scopes;

    private final String subject;

    public Consent(final IdToken idToken, final IdTokenResponse idTokenResponse) {

        this(idToken.getSub(), idToken.getAzp(), idTokenResponse.getScopes());
    }

    public Consent(final String subject, final String clientId, final Set<Scope> scopes) {

        this.subject = subject;
        this.clientId = clientId;
        this.scopes = scopes;
    }

    @Override
    public boolean equals(final Object obj) {

        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Consent other = (Consent) obj;
        if (clientId == null) {
            if (other.clientId != null) {
                return false;
            }
        } else if (!clientId.equals(other.clientId)) {
            return false;
        }
        if (scopes == null) {
            if (other.scopes != null) {
                return false;
            }
        } else if (!scopes.equals(other.scopes)) {
            return false;
        }
        if (subject == null) {
            if (other.subject != null) {
                return false;
            }
        } else if (!subject.equals(other.subject)) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {

        return Objects.hash(clientId, scopes, subject);
    }

}
