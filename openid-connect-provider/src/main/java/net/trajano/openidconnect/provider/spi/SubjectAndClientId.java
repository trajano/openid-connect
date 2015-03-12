package net.trajano.openidconnect.provider.spi;

import java.io.Serializable;

/**
 * A {@link TokenStorage} lookup key containing the subject and client id.
 * 
 * @author Archimedes
 */
public class SubjectAndClientId implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = -7366727338405104035L;

    private final String clientId;

    private final String subject;

    public SubjectAndClientId(final String subject, final String clientId) {

        this.subject = subject;
        this.clientId = clientId;
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
        final SubjectAndClientId other = (SubjectAndClientId) obj;
        if (clientId == null) {
            if (other.clientId != null) {
                return false;
            }
        } else if (!clientId.equals(other.clientId)) {
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

        final int prime = 31;
        int result = 1;
        result = prime * result + (clientId == null ? 0 : clientId.hashCode());
        result = prime * result + (subject == null ? 0 : subject.hashCode());
        return result;
    }

}
