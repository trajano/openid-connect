package net.trajano.openidconnect.core;

import java.util.Date;
import java.util.Locale;

import javax.json.JsonObject;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * <p>
 * The UserInfo Claims MUST be returned as the members of a JSON object. The
 * response body SHOULD be encoded using UTF-8. The Claims defined in Section
 * 2.5 can be returned, as can additional Claims not specified there.
 * </p>
 * <p>
 * If a Claim is not returned, that Claim Name SHOULD be omitted from the JSON
 * object representing the Claims; it SHOULD NOT be present with a null or empty
 * string value.
 * </p>
 * <p>
 * The sub (subject) Claim MUST always be returned in the UserInfo Response.
 * </p>
 * <p>
 * NOTE: The UserInfo Endpoint response is not guaranteed to be about the
 * End-User identified by the sub (subject) element of the ID Token. The sub
 * Claim in the UserInfo Endpoint response MUST be verified to exactly match the
 * sub Claim in the ID Token before using additional UserInfo Endpoint Claims.
 * </p>
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Userinfo {

    /**
     * End-User's preferred address. The value of the address member is a JSON
     * [RFC4627] structure containing some or all of the members defined in
     * Section 2.5.1.
     */
    @XmlElement(name = "address")
    private JsonObject address;

    /**
     * End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004]
     * YYYY-MM-DD format. The year MAY be 0000, indicating that it is omitted.
     * To represent only the year, YYYY format is allowed. Note that depending
     * on the underlying platform's date related function, providing just year
     * can result in varying month and day, so the implementers need to take
     * this factor into account to correctly process the dates.
     */
    @XmlElement(name = "birthdate")
    private String birthdate;

    /**
     * End-User's preferred e-mail address. Its value MUST conform to the RFC
     * 5322 [RFC5322] addr-spec syntax. This value MUST NOT be relied upon to be
     * unique by the RP, as discussed in Section 2.5.3.
     */
    @XmlElement(name = "email")
    private String email;

    /**
     * True if the End-User's e-mail address has been verified; otherwise false.
     * When this Claim Value is true, this means that the OP took affirmative
     * steps to ensure that this e-mail address was controlled by the End-User
     * at the time the verification was performed. The means by which an e-mail
     * address is verified is context-specific, and dependent upon the trust
     * framework or contractual agreements within which the parties are
     * operating.
     */
    @XmlElement(name = "email_verified")
    private Boolean emailVerified;

    /**
     * Surname(s) or last name(s) of the End-User. Note that in some cultures,
     * people can have multiple family names or no family name; all can be
     * present, with the names being separated by space characters.
     */
    @XmlElement(name = "family_name")
    private String familyName;

    /**
     * End-User's gender. Values defined by this specification are female and
     * male. Other values MAY be used when neither of the defined values are
     * applicable.
     */
    @XmlElement(name = "gender")
    private String gender;

    /**
     * Given name(s) or first name(s) of the End-User. Note that in some
     * cultures, people can have multiple given names; all can be present, with
     * the names being separated by space characters.
     */
    @XmlElement(name = "given_name")
    private String givenName;

    /**
     * End-User's locale, represented as a BCP47 [RFC5646] language tag. This is
     * typically an ISO 639-1 Alpha-2 [ISO639‑1] language code in lowercase and
     * an ISO 3166-1 Alpha-2 [ISO3166‑1] country code in uppercase, separated by
     * a dash. For example, en-US or fr-CA. As a compatibility note, some
     * implementations have used an underscore as the separator rather than a
     * dash, for example, en_US; Implementations MAY choose to accept this
     * locale syntax as well.
     */
    @XmlElement(name = "locale")
    private Locale locale;

    /**
     * Middle name(s) of the End-User. Note that in some cultures, people can
     * have multiple middle names; all can be present, with the names being
     * separated by space characters. Also note that in some cultures, middle
     * names are not used.
     */
    @XmlElement(name = "middle_name")
    private String middleName;

    /**
     * End-User's full name in displayable form including all name parts,
     * possibly including titles and suffixes, ordered according to the
     * End-User's locale and preferences.
     */
    @XmlElement(name = "name")
    private String name;

    /**
     * Casual name of the End-User that may or may not be the same as the
     * given_name. For instance, a nickname value of Mike might be returned
     * alongside a given_name value of Michael.
     */
    @XmlElement(name = "nickname")
    private String nickname;

    /**
     * End-User's preferred telephone number. E.164 [E.164] is RECOMMENDED as
     * the format of this Claim, for example, +1 (425) 555-1212 or +56 (2) 687
     * 2400. If the phone number contains an extension, it is RECOMMENDED that
     * the extension be represented using the RFC 3966 [RFC3966] extension
     * syntax, for example, +1 (604) 555-1234;ext=5678.
     */
    @XmlElement(name = "phone_number")
    private String phoneNumber;

    /**
     * True if the End-User's phone number has been verified; otherwise false.
     * When this Claim Value is true, this means that the OP took affirmative
     * steps to ensure that this phone number was controlled by the End-User at
     * the time the verification was performed. The means by which a phone
     * number is verified is context-specific, and dependent upon the trust
     * framework or contractual agreements within which the parties are
     * operating. When true, the phone_number Claim MUST be in E.164 format and
     * any extensions MUST be represented in RFC 3966 format.
     */
    @XmlElement(name = "phone_number_verified")
    private Boolean phoneNumberVerified;

    /**
     * URL of the End-User's profile picture. This URL MUST refer to an image
     * file (for example, a PNG, JPEG, or GIF image file), rather than to a Web
     * page containing an image. Note that this URL SHOULD specifically
     * reference a profile photo of the End-User suitable for displaying when
     * describing the End-User, rather than an arbitrary photo taken by the
     * End-User.
     */
    @XmlElement(name = "picture")
    private String picture;

    /**
     * Shorthand name that the End-User wishes to be referred to at the RP, such
     * as janedoe or j.doe. This value MAY be any valid JSON string including
     * special characters such as @, /, or whitespace. This value MUST NOT be
     * relied upon to be unique by the RP. (See Section 2.5.3.)
     */
    @XmlElement(name = "preferred_username")
    private String preferredUsername;

    /**
     * URL of the End-User's profile page. The contents of this Web page SHOULD
     * be about the End-User.
     */
    @XmlElement(name = "profile")
    private String profile;

    /**
     * Subject - Identifier for the End-User at the Issuer.
     */
    @XmlElement(name = "sub", required = true)
    private String sub;

    /**
     * Time the End-User's information was last updated. The time is represented
     * as the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until
     * the date/time.
     */
    @XmlElement(name = "updated_at")
    private long updatedAt;

    /**
     * URL of the End-User's Web page or blog. This Web page SHOULD contain
     * information published by the End-User or an organization that the
     * End-User is affiliated with.
     */
    @XmlElement(name = "website")
    private String website;

    /**
     * String from zoneinfo [zoneinfo] time zone database representing the
     * End-User's time zone. For example, Europe/Paris or America/Los_Angeles.
     */
    @XmlElement(name = "zoneinfo")
    private String zoneinfo;

    public JsonObject getAddress() {

        return address;
    }

    public String getBirthdate() {

        return birthdate;
    }

    public String getEmail() {

        return email;
    }

    public String getFamilyName() {

        return familyName;
    }

    public String getGender() {

        return gender;
    }

    public String getGivenName() {

        return givenName;
    }

    public Locale getLocale() {

        return locale;
    }

    public String getMiddleName() {

        return middleName;
    }

    public String getName() {

        return name;
    }

    public String getNickname() {

        return nickname;
    }

    public String getPhoneNumber() {

        return phoneNumber;
    }

    public String getPicture() {

        return picture;
    }

    public String getPreferredUsername() {

        return preferredUsername;
    }

    public String getProfile() {

        return profile;
    }

    public String getSub() {

        return sub;
    }

    public long getUpdatedAt() {

        return updatedAt;
    }

    public String getWebsite() {

        return website;
    }

    public String getZoneinfo() {

        return zoneinfo;
    }

    public boolean isEmailVerified() {

        return emailVerified;
    }

    public boolean isPhoneNumberVerified() {

        return phoneNumberVerified;
    }

    public void setAddress(final JsonObject address) {

        this.address = address;
    }

    public void setBirthdate(final String birthdate) {

        this.birthdate = birthdate;
    }

    public void setEmail(final String email) {

        this.email = email;
    }

    public void setEmailVerified(final boolean emailVerified) {

        this.emailVerified = emailVerified;
    }

    public void setFamilyName(final String familyName) {

        this.familyName = familyName;
    }

    public void setGender(final String gender) {

        this.gender = gender;
    }

    public void setGivenName(final String givenName) {

        this.givenName = givenName;
    }

    public void setLocale(final Locale locale) {

        this.locale = locale;
    }

    public void setMiddleName(final String middleName) {

        this.middleName = middleName;
    }

    public void setName(final String name) {

        this.name = name;
    }

    public void setNickname(final String nickname) {

        this.nickname = nickname;
    }

    public void setPhoneNumber(final String phoneNumber) {

        this.phoneNumber = phoneNumber;
    }

    public void setPhoneNumberVerified(final boolean phoneNumberVerified) {

        this.phoneNumberVerified = phoneNumberVerified;
    }

    public void setPicture(final String picture) {

        this.picture = picture;
    }

    public void setPreferredUsername(final String preferredUsername) {

        this.preferredUsername = preferredUsername;
    }

    public void setProfile(final String profile) {

        this.profile = profile;
    }

    public void setSub(final String sub) {

        this.sub = sub;
    }

    public void setUpdatedAt(final long updatedAt) {

        this.updatedAt = updatedAt;
    }

    public void setUpdatedAt(final Date updatedAt) {

        this.updatedAt = updatedAt.getTime() / 1000;
    }

    public void setWebsite(final String website) {

        this.website = website;
    }

    public void setZoneinfo(final String zoneinfo) {

        this.zoneinfo = zoneinfo;
    }

}
