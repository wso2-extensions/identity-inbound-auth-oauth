package org.wso2.carbon.identity.oauth2.dcr.endpoint.dto;

import java.util.ArrayList;
import java.util.List;

import io.swagger.annotations.*;
import com.fasterxml.jackson.annotation.*;

import javax.validation.constraints.NotNull;


@ApiModel(description = "")
public class UpdateRequestDTO {

    private List<String> redirectUris = new ArrayList<>();
    private String clientName = null;
    private List<String> grantTypes = new ArrayList<>();
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
    private String tokenEndpointAuthMethod = null;
    private String tokenEndpointAuthSigningAlg = null;
    private String sectorIdentifierUri = null;
    private String idTokenSignedResponseAlg = null;
    private String idTokenEncryptedResponseAlg = null;
    private String idTokenEncryptedResponseEnc = null;
    private String authorizationEncryptedResponseAlg = null;
    private String authorizationSignedResponseAlg = null;
    private String authorizationEncryptedResponseEnc = null;
    private String requestObjectSigningAlg = null;
    private String tlsClientAuthSubjectDn = null;

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
    @JsonProperty("token_endpoint_auth_signing_alg")
    public String getTokenEndpointAuthSigningAlg() {
        return tokenEndpointAuthSigningAlg;
    }
    public void setTokenEndpointAuthSigningAlg(String tokenEndpointAuthSigningAlg) {
        this.tokenEndpointAuthSigningAlg = tokenEndpointAuthSigningAlg;
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
    @JsonProperty("authorization_encrypted_response_alg")
    public String getAuthorizationEncryptedResponseAlg() {
        return authorizationEncryptedResponseAlg;
    }
    public void setAuthorizationEncryptedResponseAlg(String authorizationEncryptedResponseAlg) {
        this.authorizationEncryptedResponseAlg = authorizationEncryptedResponseAlg;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("authorization_signed_response_alg")
    public String getAuthorizationSignedResponseAlg() {
        return authorizationSignedResponseAlg;
    }
    public void setAuthorizationSignedResponseAlg(String authorizationSignedResponseAlg) {
        this.authorizationSignedResponseAlg = authorizationSignedResponseAlg;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("authorization_encrypted_response_enc")
    public String getAuthorizationEncryptedResponseEnc() {
        return authorizationEncryptedResponseEnc;
    }
    public void setAuthorizationEncryptedResponseEnc(String authorizationEncryptedResponseEnc) {
        this.authorizationEncryptedResponseEnc = authorizationEncryptedResponseEnc;
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


    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("class UpdateRequestDTO {\n");

        sb.append("  redirectUris: ").append(redirectUris).append("\n");
        sb.append("  clientName: ").append(clientName).append("\n");
        sb.append("  clientId: ").append(clientId).append("\n");
        sb.append("  clientSecret: ").append(clientSecret).append("\n");
        sb.append("  grantTypes: ").append(grantTypes).append("\n");
        sb.append("  backchannelLogoutUri: ").append(backchannelLogoutUri).append("\n");
        sb.append("  backchannelLogoutSessionRequired: ").append(backchannelLogoutSessionRequired).append("\n");
        sb.append("  extApplicationDisplayName: ").append(extApplicationDisplayName).append("\n");
        sb.append("  tokenTypeExtension: ").append(tokenType).append("\n");
        sb.append("  extApplicationOwner: ").append(extApplicationOwner).append("\n");
        sb.append("  extApplicationTokenLifetime: ").append(extApplicationTokenLifetime).append("\n");
        sb.append("  extUserTokenLifetime: ").append(extUserTokenLifetime).append("\n");
        sb.append("  extRefreshTokenLifetime: ").append(extRefreshTokenLifetime).append("\n");
        sb.append("  extIdTokenLifetime: ").append(extIdTokenLifetime).append("\n");
        sb.append("  extPkceMandatory: ").append(extPkceMandatory).append("\n");
        sb.append("  extPkceSupportPlain: ").append(extPkceSupportPlain).append("\n");
        sb.append("  extPublicClient: ").append(extPublicClient).append("\n");
        sb.append("  tokenEndpointAuthMethod: ").append(tokenEndpointAuthMethod).append("\n");
        sb.append("  tokenEndpointAuthSigningAlg: ").append(tokenEndpointAuthSigningAlg).append("\n");
        sb.append("  sectorIdentifierUri: ").append(sectorIdentifierUri).append("\n");
        sb.append("  idTokenSignedResponseAlg: ").append(idTokenSignedResponseAlg).append("\n");
        sb.append("  idTokenEncryptedResponseAlg: ").append(idTokenEncryptedResponseAlg).append("\n");
        sb.append("  idTokenEncryptedResponseEnc: ").append(idTokenEncryptedResponseEnc).append("\n");
        sb.append("  authorizationEncryptedResponseAlg: ").append(authorizationEncryptedResponseAlg).append("\n");
        sb.append("  authorizationSignedResponseAlg: ").append(authorizationSignedResponseAlg).append("\n");
        sb.append("  authorizationEncryptedResponseEnc: ").append(authorizationEncryptedResponseEnc).append("\n");
        sb.append("  requestObjectSigningAlg: ").append(requestObjectSigningAlg).append("\n");
        sb.append("  tlsClientAuthSubjectDn: ").append(tlsClientAuthSubjectDn).append("\n");
        sb.append("}\n");
        return sb.toString();
    }
}
