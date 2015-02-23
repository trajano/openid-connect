package net.trajano.openidconnect.crypto;

import javax.xml.bind.annotation.XmlEnumValue;

public enum KeyType {
    /**
     * Elliptic Curve.
     */
    EC,

    /**
     * Octet sequence.
     */
    @XmlEnumValue("oct")
    oct,

    /**
     * RSA.
     */
    RSA
}
