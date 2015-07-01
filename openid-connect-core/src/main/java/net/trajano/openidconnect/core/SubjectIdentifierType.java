package net.trajano.openidconnect.core;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;

/**
 * Subject identifier types. A Subject Identifier is a locally unique and never
 * reassigned identifier within the Issuer for the End-User, which is intended
 * to be consumed by the Client. Two Subject Identifier types are defined by
 * this specification.: {@link #PUBLIC} and {@link #PAIRWISE}. The OpenID
 * Provider's Discovery document SHOULD list its supported Subject Identifier
 * types in the subject_types_supported element. If there is more than one type
 * listed in the array, the Client MAY elect to provide its preferred identifier
 * type using the subject_type parameter during Registration.
 * 
 * @author Archimedes
 */
@XmlEnum
public enum SubjectIdentifierType {
    /**
     * This provides the same sub (subject) value to all Clients. It is the
     * default if the provider has no subject_types_supported element in its
     * discovery document.
     */
    @XmlEnumValue("public") PUBLIC,
    /**
     * This provides a different sub value to each Client, so as not to enable
     * Clients to correlate the End-User's activities without permission.
     */
    @XmlEnumValue("pairwise") pairwise
}
