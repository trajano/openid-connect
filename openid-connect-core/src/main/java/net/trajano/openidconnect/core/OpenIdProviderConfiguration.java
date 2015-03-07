package net.trajano.openidconnect.core;

import java.net.URI;
import java.util.Locale;
import java.util.Set;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import net.trajano.openidconnect.crypto.JsonWebAlgorithm;

/**
 * <p>
 * The response is a set of Claims about the OpenID Provider's configuration,
 * including all necessary endpoints and public key location information. A
 * successful response MUST use the 200 OK HTTP status code and return a JSON
 * object using the application/json content type that contains a set of Claims
 * as its members that are a subset of the Metadata values defined in Section 3.
 * Other Claims MAY also be returned.
 * </p>
 * <p>
 * Claims that return multiple values are represented as JSON arrays. Claims
 * with zero elements MUST be omitted from the response.
 * </p>
 * <p>
 * An error response uses the applicable HTTP status code value.
 * </p>
 */
@XmlRootElement
public class OpenIdProviderConfiguration {

    /**
     * <p>
     * request_object_encryption_alg_values_supported
     * </p>
     * <p>
     * OPTIONAL. JSON array containing a list of the JWE encryption algorithms
     * (alg values) supported by the Authorization Server for the Request Object
     * described in Section 2.9 of OpenID Connect Messages 1.0
     * [OpenID.Messages]. These algorithms are used both when the Request Object
     * is passed by value and when it is passed by reference.
     * </p>
     */
    @XmlElement(name = "request_object_encryption_alg_values_supported")
    private Set<JsonWebAlgorithm> requestObjectEncryptionAlgValuesSupported;

    
    public Set<JsonWebAlgorithm> getRequestObjectEncryptionAlgValuesSupported() {
    
        return requestObjectEncryptionAlgValuesSupported;
    }

    
    public void setRequestObjectEncryptionAlgValuesSupported(Set<JsonWebAlgorithm> requestObjectEncryptionAlgValuesSupported) {
    
        this.requestObjectEncryptionAlgValuesSupported = requestObjectEncryptionAlgValuesSupported;
    }

    
    public Set<JsonWebAlgorithm> getRequestObjectEncryptionEncValuesSupported() {
    
        return requestObjectEncryptionEncValuesSupported;
    }

    
    public void setRequestObjectEncryptionEncValuesSupported(Set<JsonWebAlgorithm> requestObjectEncryptionEncValuesSupported) {
    
        this.requestObjectEncryptionEncValuesSupported = requestObjectEncryptionEncValuesSupported;
    }

    
    public URI getCheckSessionIframe() {
    
        return checkSessionIframe;
    }

    
    public void setCheckSessionIframe(URI checkSessionIframe) {
    
        this.checkSessionIframe = checkSessionIframe;
    }

    /**
     * <p>
     * request_object_encryption_enc_values_supported
     * </p>
     * <p>
     * OPTIONAL. JSON array containing a list of the JWE encryption algorithms
     * (enc values) supported by the Authorization Server for the Request Object
     * described in Section 2.9 of OpenID Connect Messages 1.0
     * [OpenID.Messages]. These algorithms are used both when the Request Object
     * is passed by value and when it is passed by reference.
     * </p>
     */
    @XmlElement(name = "request_object_encryption_enc_values_supported")
    private Set<JsonWebAlgorithm> requestObjectEncryptionEncValuesSupported;

    /**
     * JSON array containing a list of the Authentication Context Class
     * References that this OP supports.
     */
    @XmlElement(name = "acr_values_supported")
    private Set<String> acrValuesSupported;

    /**
     * URL of the OP's OAuth 2.0 Authorization Endpoint [OpenID.Core].
     */
    @XmlElement(name = "authorization_endpoint")
    private URI authorizationEndpoint;

    /**
     * URL of an OP iframe that supports cross-origin communications for session
     * state information with the RP Client, using the HTML5 postMessage API.
     * The page is loaded from an invisible iframe embedded in an RP page so
     * that it can run in the OP's security context. It accepts postMessage
     * requests from the relevant RP iframe and uses postMessage to post back
     * the login status of the End-User at the OP.
     */
    @XmlElement(name = "check_session_iframe")
    private URI checkSessionIframe;

    /**
     * Boolean value specifying whether the OP supports use of the claims
     * parameter, with true indicating support. If omitted, the default value is
     * <code>false</code>.
     */
    @XmlElement(name = "claims_parameter_supported")
    private boolean claimsParameterSupported;

    @XmlElement(name = "claims_supported")
    private Set<String> claimsSupported;

    @XmlElement(name = "claim_types_supported")
    private Set<String> claimTypesSupported;

    @XmlElement(name = "display_values_supported")
    private Set<String> displayValuesSupported;

    /**
     * URL at the OP to which an RP can perform a redirect to request that the
     * End-User be logged out at the OP.
     */
    @XmlElement(name = "end_session_endpoint")
    private URI endSessionEndpoint;

    @XmlElement(name = "id_token_encryption_alg_values_supported")
    private Set<JsonWebAlgorithm> idTokenEncryptionAlgValuesSupported;

    @XmlElement(name = "id_token_encryption_enc_values_supported")
    private Set<JsonWebAlgorithm> idTokenEncryptionEncValuesSupported;

    @XmlElement(name = "id_token_signing_alg_values_supported")
    private Set<JsonWebAlgorithm> idTokenSigningAlgValuesSupported;

    /**
     * URL using the https scheme with no query or fragment component that the
     * OP asserts as its Issuer Identifier. If Issuer discovery is supported
     * (see Section 2), this value MUST be identical to the issuer value
     * returned by WebFinger. This also MUST be identical to the iss Claim value
     * in ID Tokens issued from this Issuer.
     * <p>
     * In order to support Google, this is left as a string rather than a URI.
     */
    private String issuer;

    /**
     * URL of the OP's JSON Web Key Set [JWK] document. This contains the
     * signing key(s) the RP uses to validate signatures from the OP. The JWK
     * Set MAY also contain the Server's encryption key(s), which are used by
     * RPs to encrypt requests to the Server. When both signing and encryption
     * keys are made available, a use (Key Use) parameter value is REQUIRED for
     * all keys in the referenced JWK Set to indicate each key's intended usage.
     * Although some algorithms allow the same key to be used for both
     * signatures and encryption, doing so is NOT RECOMMENDED, as it is less
     * secure. The JWK x5c parameter MAY be used to provide X.509
     * representations of keys provided. When used, the bare key values MUST
     * still be present and MUST match those in the certificate.
     */
    @XmlElement(name = "jwks_uri")
    private URI jwksUri;

    /**
     * URL of the OP's Dynamic Client Registration Endpoint.
     */
    @XmlElement(name = "registration_endpoint")
    private URI registrationEndpoint;

    @XmlElement(name = "request_object_signing_alg_values_supported")
    private Set<JsonWebAlgorithm> requestObjectSigningAlgValuesSupported;

    /**
     * Boolean value specifying whether the OP supports use of the request
     * parameter, with true indicating support. If omitted, the default value is
     * <code>false</code>.
     */
    @XmlElement(name = "request_parameter_supported")
    private boolean requestParameterSupported;

    /**
     * Boolean value specifying whether the OP supports use of the request_uri
     * parameter, with true indicating support. If omitted, the default value is
     * true.
     */
    @XmlElement(name = "request_uri_parameter_supported")
    private final boolean requestUriParameterSupported = true;

    /**
     * Boolean value specifying whether the OP requires any request_uri values
     * used to be pre-registered using the request_uris registration parameter.
     * Pre-registration is REQUIRED when the value is true. If omitted, the
     * default value is false.
     */
    @XmlElement(name = "require_request_uri_registration")
    private boolean requireRequestUriRegistration;

    /**
     * JSON array containing a list of the OAuth 2.0 response_type values that
     * this OP supports. Dynamic OpenID Providers MUST support the code,
     * id_token, and the token id_token Response Type values.
     */
    @XmlElement(name = "response_types_supported")
    private Set<String> responseTypesSupported;

    @XmlElement(name = "revocation_endpoint")
    private URI revocationEndpoint;

    /**
     * JSON array containing a list of the OAuth 2.0 [RFC6749] scope values that
     * this server supports. The server MUST support the openid scope value.
     * Servers MAY choose not to advertise some supported scope values even when
     * this parameter is used, although those defined in [OpenID.Core] SHOULD be
     * listed, if supported.
     */
    @XmlElement(name = "scopes_supported")
    private Set<String> scopesSupported;

    /**
     * URL of a page containing human-readable information that developers might
     * want or need to know when using the OpenID Provider. In particular, if
     * the OpenID Provider does not support Dynamic Client Registration, then
     * information on how to register Clients needs to be provided in this
     * documentation.
     */
    @XmlElement(name = "service_documentation")
    private URI serviceDocumentation;

    @XmlElement(name = "subject_types_supported")
    private Set<String> subjectTypesSupported;

    /**
     * URL of the OP's OAuth 2.0 Token Endpoint [OpenID.Core]. This is REQUIRED
     * unless only the Implicit Flow is used.
     */
    @XmlElement(name = "token_endpoint")
    private URI tokenEndpoint;

    @XmlElement(name = "token_endpoint_auth_methods_supported")
    Set<String> tokenEndpointAuthMethodsSupported;

    @XmlElement(name = "token_endpoint_auth_signing_alg_values_supported")
    private Set<JsonWebAlgorithm> tokenEndpointAuthSigningAlgValuesSupported;

    @XmlElement(name = "ui_locales_supported")
    private Set<Locale> uiLocalesSupported;

    @XmlElement(name = "userinfo_encryption_alg_values_supported")
    private Set<JsonWebAlgorithm> userinfoEncryptionAlgValuesSupported;

    @XmlElement(name = "userinfo_encryption_enc_values_supported")
    private Set<JsonWebAlgorithm> userinfoEncryptionEncValuesSupported;

    /**
     * URL of the OP's UserInfo Endpoint [OpenID.Core]. This URL MUST use the
     * https scheme and MAY contain port, path, and query parameter components.
     */
    @XmlElement(name = "userinfo_endpoint")
    private URI userinfoEndpoint;

    @XmlElement(name = "userinfo_signing_alg_values_supported")
    private Set<JsonWebAlgorithm> userinfoSigningAlgValuesSupported;

    public Set<String> getAcrValuesSupported() {

        return acrValuesSupported;
    }

    public URI getAuthorizationEndpoint() {

        return authorizationEndpoint;
    }

    public Set<String> getClaimsSupported() {

        return claimsSupported;
    }

    public Set<String> getClaimTypesSupported() {

        return claimTypesSupported;
    }

    public Set<String> getDisplayValuesSupported() {

        return displayValuesSupported;
    }

    public URI getEndSessionEndpoint() {

        return endSessionEndpoint;
    }

    public Set<JsonWebAlgorithm> getIdTokenEncryptionAlgValuesSupported() {

        return idTokenEncryptionAlgValuesSupported;
    }

    public Set<JsonWebAlgorithm> getIdTokenEncryptionEncValuesSupported() {

        return idTokenEncryptionEncValuesSupported;
    }

    public Set<JsonWebAlgorithm> getIdTokenSigningAlgValuesSupported() {

        return idTokenSigningAlgValuesSupported;
    }

    public String getIssuer() {

        return issuer;
    }

    public URI getJwksUri() {

        return jwksUri;
    }

    public URI getRegistrationEndpoint() {

        return registrationEndpoint;
    }

    public Set<JsonWebAlgorithm> getRequestObjectSigningAlgValuesSupported() {

        return requestObjectSigningAlgValuesSupported;
    }

    public Set<String> getResponseTypesSupported() {

        return responseTypesSupported;
    }

    public URI getRevocationEndpoint() {

        return revocationEndpoint;
    }

    public Set<String> getScopesSupported() {

        return scopesSupported;
    }

    public URI getServiceDocumentation() {

        return serviceDocumentation;
    }

    public Set<String> getSubjectTypesSupported() {

        return subjectTypesSupported;
    }

    public URI getTokenEndpoint() {

        return tokenEndpoint;
    }

    public Set<String> getTokenEndpointAuthMethodsSupported() {

        return tokenEndpointAuthMethodsSupported;
    }

    public Set<JsonWebAlgorithm> getTokenEndpointAuthSigningAlgValuesSupported() {

        return tokenEndpointAuthSigningAlgValuesSupported;
    }

    public Set<Locale> getUiLocalesSupported() {

        return uiLocalesSupported;
    }

    public Set<JsonWebAlgorithm> getUserinfoEncryptionAlgValuesSupported() {

        return userinfoEncryptionAlgValuesSupported;
    }

    public Set<JsonWebAlgorithm> getUserinfoEncryptionEncValuesSupported() {

        return userinfoEncryptionEncValuesSupported;
    }

    public URI getUserinfoEndpoint() {

        return userinfoEndpoint;
    }

    public Set<JsonWebAlgorithm> getUserinfoSigningAlgValuesSupported() {

        return userinfoSigningAlgValuesSupported;
    }

    public boolean isClaimsParameterSupported() {

        return claimsParameterSupported;
    }

    public boolean isRequestParameterSupported() {

        return requestParameterSupported;
    }

    public boolean isRequestUriParameterSupported() {

        return requestUriParameterSupported;
    }

    public boolean isRequireRequestUriRegistration() {

        return requireRequestUriRegistration;
    }

    public void setAcrValuesSupported(final Set<String> acrValuesSupported) {

        this.acrValuesSupported = acrValuesSupported;
    }

    public void setAuthorizationEndpoint(final URI authorizationEndpoint) {

        this.authorizationEndpoint = authorizationEndpoint;
    }

    public void setClaimsParameterSupported(final boolean claimsParameterSupported) {

        this.claimsParameterSupported = claimsParameterSupported;
    }

    public void setClaimsSupported(final Set<String> claimsSupported) {

        this.claimsSupported = claimsSupported;
    }

    public void setClaimTypesSupported(final Set<String> claimTypesSupported) {

        this.claimTypesSupported = claimTypesSupported;
    }

    public void setDisplayValuesSupported(final Set<String> displayValuesSupported) {

        this.displayValuesSupported = displayValuesSupported;
    }

    public void setEndSessionEndpoint(final URI endSessionEndpoint) {

        this.endSessionEndpoint = endSessionEndpoint;
    }

    public void setIdTokenEncryptionAlgValuesSupported(final Set<JsonWebAlgorithm> idTokenEncryptionAlgValuesSupported) {

        this.idTokenEncryptionAlgValuesSupported = idTokenEncryptionAlgValuesSupported;
    }

    public void setIdTokenEncryptionEncValuesSupported(final Set<JsonWebAlgorithm> idTokenEncryptionEncValuesSupported) {

        this.idTokenEncryptionEncValuesSupported = idTokenEncryptionEncValuesSupported;
    }

    public void setIdTokenSigningAlgValuesSupported(final Set<JsonWebAlgorithm> idTokenSigningAlgValuesSupported) {

        this.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported;
    }

    public void setIssuer(final String issuer) {

        this.issuer = issuer;
    }

    public void setJwksUri(final URI jwksUri) {

        this.jwksUri = jwksUri;
    }

    public void setRegistrationEndpoint(final URI registrationEndpoint) {

        this.registrationEndpoint = registrationEndpoint;
    }

    public void setRequestObjectSigningAlgValuesSupported(final Set<JsonWebAlgorithm> requestObjectSigningAlgValuesSupported) {

        this.requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported;
    }

    public void setRequestParameterSupported(final boolean requestParameterSupported) {

        this.requestParameterSupported = requestParameterSupported;
    }

    public void setRequireRequestUriRegistration(final boolean requireRequestUriRegistration) {

        this.requireRequestUriRegistration = requireRequestUriRegistration;
    }

    public void setResponseTypesSupported(final Set<String> responseTypesSupported) {

        this.responseTypesSupported = responseTypesSupported;
    }

    public void setRevocationEndpoint(final URI revocationEndpoint) {

        this.revocationEndpoint = revocationEndpoint;
    }

    public void setScopesSupported(final Set<String> scopesSupported) {

        this.scopesSupported = scopesSupported;
    }

    public void setServiceDocumentation(final URI serviceDocumentation) {

        this.serviceDocumentation = serviceDocumentation;
    }

    public void setSubjectTypesSupported(final Set<String> subjectTypesSupported) {

        this.subjectTypesSupported = subjectTypesSupported;
    }

    public void setTokenEndpoint(final URI tokenEndpoint) {

        this.tokenEndpoint = tokenEndpoint;
    }

    public void setTokenEndpointAuthMethodsSupported(final Set<String> tokenEndpointAuthMethodsSupported) {

        this.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
    }

    public void setTokenEndpointAuthSigningAlgValuesSupported(final Set<JsonWebAlgorithm> tokenEndpointAuthSigningAlgValuesSupported) {

        this.tokenEndpointAuthSigningAlgValuesSupported = tokenEndpointAuthSigningAlgValuesSupported;
    }

    public void setUiLocalesSupported(final Set<Locale> uiLocalesSupported) {

        this.uiLocalesSupported = uiLocalesSupported;
    }

    public void setUserinfoEncryptionAlgValuesSupported(final Set<JsonWebAlgorithm> userinfoEncryptionAlgValuesSupported) {

        this.userinfoEncryptionAlgValuesSupported = userinfoEncryptionAlgValuesSupported;
    }

    public void setUserinfoEncryptionEncValuesSupported(final Set<JsonWebAlgorithm> userinfoEncryptionEncValuesSupported) {

        this.userinfoEncryptionEncValuesSupported = userinfoEncryptionEncValuesSupported;
    }

    public void setUserinfoEndpoint(final URI userinfoEndpoint) {

        this.userinfoEndpoint = userinfoEndpoint;
    }

    public void setUserinfoSigningAlgValuesSupported(final Set<JsonWebAlgorithm> userinfoSigningAlgValuesSupported) {

        this.userinfoSigningAlgValuesSupported = userinfoSigningAlgValuesSupported;
    }
}
