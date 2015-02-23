package net.trajano.openidconnect.crypto;

import javax.xml.bind.annotation.XmlEnumValue;

public enum KeyUse {
    /**
     * Encryption.
     */
    @XmlEnumValue("enc")
    ENC,
    /**
     * Signature.
     */
    @XmlEnumValue("sig")
    SIG
}
