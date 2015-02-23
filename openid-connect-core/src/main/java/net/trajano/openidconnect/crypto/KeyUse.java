package net.trajano.openidconnect.crypto;

import javax.xml.bind.annotation.XmlEnumValue;

public enum KeyUse {
    /**
     * Encryption.
     */
    @XmlEnumValue("enc")
    enc,
    /**
     * Signature.
     */
    @XmlEnumValue("sig")
    sig
}
