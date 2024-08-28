package org.wso2.carbon.identity.oauth2.dcr.endpoint.dto;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

import javax.validation.constraints.NotNull;


@ApiModel(description = "")
public class UpdateRequestDTO {

    private List<String> redirectUris = new ArrayList<>();
    private String clientName = null;
    private List<String> grantTypes = new ArrayList<>();
    private String jwksUri = null;
    private String tokenType = null;
    private String clientId = null;
    private String clientSecret = null;
    private String backchannelLogoutUri = null;
    private boolean backchannelLogoutSessionRequired;
    private String extApplicationDisplayName = null;
    private String extApplicationOwner = null;
    private Long extApplicationTokenLifetime = null;
    private Long extUserTokenLifetime = null;
    private Long extRefreshTokenLifetime = null;
    private Long extIdTokenLifetime = null;
    private boolean extPkceMandatory;
    private boolean extPkceSupportPlain;
    private boolean extPublicClient;
    private String extTokenType = null;
    private String tokenEndpointAuthMethod = null;
    private Boolean tokenEndpointAllowReusePvtKeyJwt;
    private String tokenEndpointAuthSigningAlg = null;
    private String sectorIdentifierUri = null;
    private String idTokenSignedResponseAlg = null;
    private String idTokenEncryptedResponseAlg = null;
    private String idTokenEncryptedResponseEnc = null;
    private String requestObjectSigningAlg = null;
    private String tlsClientAuthSubjectDn = null;
    private boolean requirePushAuthorizationRequest;
    private boolean requireSignedRequestObject;
    private boolean tlsClientCertificateBoundAccessToken;
    private String subjectType = null;
    private String requestObjectEncryptionAlgorithm = null;
    private String requestObjectEncryptionMethod = null;
    private String softwareStatement = null;
    private Boolean useClientIdAsSubClaimForAppTokens;
    private Boolean omitUsernameInIntrospectionRespForAppTokens;
    private final Map<String, Object> additionalAttributes = new HashMap<>();
    private String extAllowedAudience;

    @ApiModelProperty(value = "")
    @JsonProperty("redirect_uris")
    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(List<String> redirectUris) {
        this.redirectUris = redirectUris;
    }

    @ApiModelProperty
    @JsonProperty("client_name")
    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    @ApiModelProperty
    @JsonProperty("grant_types")
    public List<String> getGrantTypes() {
        return grantTypes;
    }

    public void setGrantTypes(List<String> grantTypes) {
        this.grantTypes = grantTypes;
    }

    @ApiModelProperty
    @JsonProperty("token_type_extension")
    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    @ApiModelProperty
    @JsonProperty("ext_token_type")
    public String getExtTokenType() {
        return extTokenType;
    }

    public void setExtTokenType(String tokenType) {
        this.extTokenType = tokenType;
    }

    @JsonProperty("client_id")
    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    @ApiModelProperty
    @JsonProperty("client_secret")
    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    @ApiModelProperty
    @JsonProperty("backchannel_logout_uri")
    public String getBackchannelLogoutUri() {
        return backchannelLogoutUri;
    }

    public void setBackchannelLogoutUri(String backchannelLogoutUri) {
        this.backchannelLogoutUri = backchannelLogoutUri;
    }

    @ApiModelProperty
    @JsonProperty("backchannel_logout_session_required")
    public boolean getBackchannelLogoutSessionRequired() {
        return backchannelLogoutSessionRequired;
    }

    public void setBackchannelLogoutSessionRequired(boolean backchannelLogoutSessionRequired) {
        this.backchannelLogoutSessionRequired = backchannelLogoutSessionRequired;
    }

    @ApiModelProperty
    @JsonProperty("ext_application_display_name")
    public String getExtApplicationDisplayName() {
        return extApplicationDisplayName;
    }

    public void setExtApplicationDisplayName(String extApplicationDisplayName) {
        this.extApplicationDisplayName = extApplicationDisplayName;
    }

    @ApiModelProperty
    @JsonProperty("ext_application_owner")
    public String getExtApplicationOwner() {
        return extApplicationOwner;
    }

    public void setExtApplicationOwner(String extApplicationOwner) {
        this.extApplicationOwner = extApplicationOwner;
    }

    @ApiModelProperty
    @JsonProperty("ext_application_token_lifetime")
    public Long getExtApplicationTokenLifetime() {
        return extApplicationTokenLifetime;
    }

    public void setExtApplicationTokenLifetime(Long extApplicationTokenLifetime) {
        this.extApplicationTokenLifetime = extApplicationTokenLifetime;
    }

    @ApiModelProperty
    @JsonProperty("ext_user_token_lifetime")
    public Long getExtUserTokenLifetime() {
        return extUserTokenLifetime;
    }

    public void setExtUserTokenLifetime(Long extUserTokenLifetime) {
        this.extUserTokenLifetime = extUserTokenLifetime;
    }

    @ApiModelProperty
    @JsonProperty("ext_refresh_token_lifetime")
    public Long getExtRefreshTokenLifetime() {
        return extRefreshTokenLifetime;
    }

    public void setExtRefreshTokenLifetime(Long extRefreshTokenLifetime) {
        this.extRefreshTokenLifetime = extRefreshTokenLifetime;
    }

    @ApiModelProperty
    @JsonProperty("ext_id_token_lifetime")
    public Long getExtIdTokenLifetime() {
        return extIdTokenLifetime;
    }

    public void setExtIdTokenLifetime(Long extIdTokenLifetime) {
        this.extIdTokenLifetime = extIdTokenLifetime;
    }

    @ApiModelProperty
    @JsonProperty("ext_pkce_mandatory")
    public boolean getExtPkceMandatory() {
        return extPkceMandatory;
    }

    public void setExtPkceMandatory(boolean extPkceMandatory) {
        this.extPkceMandatory = extPkceMandatory;
    }

    @ApiModelProperty
    @JsonProperty("ext_pkce_support_plain")
    public boolean getExtPkceSupportPlain() {
        return extPkceSupportPlain;
    }

    public void setExtPkceSupportPlain(boolean extPkceSupportPlain) {
        this.extPkceSupportPlain = extPkceSupportPlain;
    }

    @ApiModelProperty
    @JsonProperty("ext_public_client")
    public boolean getExtPublicClient() {
        return extPublicClient;
    }

    public void setExtPublicClient(boolean extPublicClient) {
        this.extPublicClient = extPublicClient;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("token_endpoint_auth_method")
    public String getTokenEndpointAuthMethod() {
        return tokenEndpointAuthMethod;
    }

    public void setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {
        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("token_endpoint_allow_reuse_pvt_key_jwt")
    public Boolean isTokenEndpointAllowReusePvtKeyJwt() {

        return tokenEndpointAllowReusePvtKeyJwt;
    }

    public void setTokenEndpointAllowReusePvtKeyJwt(Boolean tokenEndpointAllowReusePvtKeyJwt) {

        this.tokenEndpointAllowReusePvtKeyJwt = tokenEndpointAllowReusePvtKeyJwt;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("token_endpoint_auth_signing_alg")
    public String getTokenEndpointAuthSigningAlg() {
        return tokenEndpointAuthSigningAlg;
    }

    public void setTokenEndpointAuthSigningAlg(String tokenEndpointAuthSigningAlg) {
        this.tokenEndpointAuthSigningAlg = tokenEndpointAuthSigningAlg;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("use_client_id_as_sub_claim_for_app_tokens")
    public Boolean isUseClientIdAsSubClaimForAppTokens() {
        return useClientIdAsSubClaimForAppTokens;
    }
    public void setUseClientIdAsSubClaimForAppTokens(Boolean useClientIdAsSubClaimForAppTokens) {
        this.useClientIdAsSubClaimForAppTokens = useClientIdAsSubClaimForAppTokens;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("omit_username_in_introspection_resp_for_app_tokens")
    public Boolean isOmitUsernameInIntrospectionRespForAppTokens() {
        return omitUsernameInIntrospectionRespForAppTokens;
    }
    public void setOmitUsernameInIntrospectionRespForAppTokens(Boolean omitUsernameInIntrospectionRespForAppTokens) {
        this.omitUsernameInIntrospectionRespForAppTokens = omitUsernameInIntrospectionRespForAppTokens;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("sector_identifier_uri")
    public String getSectorIdentifierUri() {
        return sectorIdentifierUri;
    }

    public void setSectorIdentifierUri(String sectorIdentifierUri) {
        this.sectorIdentifierUri = sectorIdentifierUri;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("id_token_signed_response_alg")
    public String getIdTokenSignedResponseAlg() {
        return idTokenSignedResponseAlg;
    }

    public void setIdTokenSignedResponseAlg(String idTokenSignedResponseAlg) {
        this.idTokenSignedResponseAlg = idTokenSignedResponseAlg;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("id_token_encrypted_response_alg")
    public String getIdTokenEncryptedResponseAlg() {
        return idTokenEncryptedResponseAlg;
    }

    public void setIdTokenEncryptedResponseAlg(String idTokenEncryptedResponseAlg) {
        this.idTokenEncryptedResponseAlg = idTokenEncryptedResponseAlg;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("id_token_encrypted_response_enc")
    public String getIdTokenEncryptedResponseEnc() {
        return idTokenEncryptedResponseEnc;
    }

    public void setIdTokenEncryptedResponseEnc(String idTokenEncryptedResponseEnc) {
        this.idTokenEncryptedResponseEnc = idTokenEncryptedResponseEnc;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("request_object_signing_alg")
    public String getRequestObjectSigningAlg() {
        return requestObjectSigningAlg;
    }

    public void setRequestObjectSigningAlg(String requestObjectSigningAlg) {
        this.requestObjectSigningAlg = requestObjectSigningAlg;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("tls_client_auth_subject_dn")
    public String getTlsClientAuthSubjectDn() {
        return tlsClientAuthSubjectDn;
    }

    public void setTlsClientAuthSubjectDn(String tlsClientAuthSubjectDn) {
        this.tlsClientAuthSubjectDn = tlsClientAuthSubjectDn;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("require_pushed_authorization_requests")
    public boolean isRequirePushAuthorizationRequest() {
        return requirePushAuthorizationRequest;
    }

    public void setRequirePushAuthorizationRequest(boolean requirePushAuthorizationRequest) {
        this.requirePushAuthorizationRequest = requirePushAuthorizationRequest;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("require_signed_request_object")
    public boolean isRequireSignedRequestObject() {
        return requireSignedRequestObject;
    }

    public void setRequireSignedRequestObject(boolean requireSignedRequestObject) {
        this.requireSignedRequestObject = requireSignedRequestObject;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("tls_client_certificate_bound_access_tokens")
    public boolean isTlsClientCertificateBoundAccessToken() {
        return tlsClientCertificateBoundAccessToken;
    }

    public void setTlsClientCertificateBoundAccessToken(boolean tlsClientCertificateBoundAccessToken) {
        this.tlsClientCertificateBoundAccessToken = tlsClientCertificateBoundAccessToken;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("subject_type")
    public String getSubjectType() {
        return subjectType;
    }

    public void setSubjectType(String subjectType) {
        this.subjectType = subjectType;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("request_object_encryption_alg")
    public String getRequestObjectEncryptionAlgorithm() {
        return requestObjectEncryptionAlgorithm;
    }

    public void setRequestObjectEncryptionAlgorithm(String requestObjectEncryptionAlgorithm) {
        this.requestObjectEncryptionAlgorithm = requestObjectEncryptionAlgorithm;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("request_object_encryption_enc")
    public String getRequestObjectEncryptionMethod() {
        return requestObjectEncryptionMethod;
    }

    public void setRequestObjectEncryptionMethod(String requestObjectEncryptionMethod) {
        this.requestObjectEncryptionMethod = requestObjectEncryptionMethod;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("software_statement")
    public String getSoftwareStatement() {
        return softwareStatement;
    }
    public void setSoftwareStatement(String softwareStatement) {
        this.softwareStatement = softwareStatement;
    }

    @ApiModelProperty
    @JsonProperty("jwks_uri")
    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    @JsonAnySetter
    public void setAdditionalAttributes(String key, Object value) {
        additionalAttributes.put(key, value);
    }

    public Map<String, Object> getAdditionalAttributes() {
        return additionalAttributes;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("ext_allowed_audience")
    public String getExtAllowedAudience() {
        return extAllowedAudience;
    }
    public void setExtAllowedAudience(String extAllowedAudience) {
        this.extAllowedAudience = extAllowedAudience;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("class UpdateRequestDTO {\n");

        sb.append("  redirect_uris: ").append(redirectUris).append("\n");
        sb.append("  client_name: ").append(clientName).append("\n");
        sb.append("  grant_types: ").append(clientId).append("\n");
        sb.append("  client_secret: ").append(clientSecret).append("\n");
        sb.append("  grant_types: ").append(grantTypes).append("\n");
        sb.append("  backchannel_logout_uri: ").append(backchannelLogoutUri).append("\n");
        sb.append("  backchannel_logout_session_required: ").append(backchannelLogoutSessionRequired).append("\n");
        sb.append("  ext_application_display_name: ").append(extApplicationDisplayName).append("\n");
        sb.append("  tokenTypeExtension: ").append(tokenType).append("\n");
        sb.append("  ext_application_owner: ").append(extApplicationOwner).append("\n");
        sb.append("  ext_application_token_lifetime: ").append(extApplicationTokenLifetime).append("\n");
        sb.append("  ext_user_token_lifetime: ").append(extUserTokenLifetime).append("\n");
        sb.append("  ext_refresh_token_lifetime: ").append(extRefreshTokenLifetime).append("\n");
        sb.append("  ext_id_token_lifetime: ").append(extIdTokenLifetime).append("\n");
        sb.append("  ext_pkce_mandatory: ").append(extPkceMandatory).append("\n");
        sb.append("  ext_pkce_support_plain: ").append(extPkceSupportPlain).append("\n");
        sb.append("  ext_public_client: ").append(extPublicClient).append("\n");
        sb.append("  use_client_id_as_sub_claim_for_app_tokens: ").append(useClientIdAsSubClaimForAppTokens).append("\n");
        sb.append("  omit_username_in_introspection_resp_for_app_tokens: ")
                .append(omitUsernameInIntrospectionRespForAppTokens).append("\n");
        sb.append("  token_endpoint_auth_method: ").append(tokenEndpointAuthMethod).append("\n");
        sb.append("  token_endpoint_auth_signing_alg: ").append(tokenEndpointAuthSigningAlg).append("\n");
        sb.append("  sector_identifier_uri: ").append(sectorIdentifierUri).append("\n");
        sb.append("  id_token_signed_response_alg: ").append(idTokenSignedResponseAlg).append("\n");
        sb.append("  id_token_encrypted_response_alg: ").append(idTokenEncryptedResponseAlg).append("\n");
        sb.append("  id_token_encrypted_response_enc: ").append(idTokenEncryptedResponseEnc).append("\n");
        sb.append("  request_object_signing_alg: ").append(requestObjectSigningAlg).append("\n");
        sb.append("  tls_client_auth_subject_dn: ").append(tlsClientAuthSubjectDn).append("\n");
        sb.append("  additionalAttributes: ").append(additionalAttributes).append("\n");
        sb.append("  extAllowedAudience: ").append(extAllowedAudience).append("\n");
        sb.append("}\n");
        return sb.toString();
    }
}
