package org.wso2.carbon.identity.oauth2.dcr.endpoint.dto;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.swagger.annotations.*;
import com.fasterxml.jackson.annotation.*;

import javax.validation.constraints.NotNull;

@ApiModel(description = "")
public class ApplicationDTO  {
  
  
  
  private String clientId = null;
  
  
  private String clientSecret = null;
  
  
  private Long clientSecretExpiresAt = null;
  
  
  private List<String> redirectUris = new ArrayList<String>();
  
  
  private List<String> grantTypes = new ArrayList<String>();


    private String clientName = null;


    private String extApplicationDisplayName = null;


    private String extApplicationOwner = null;


    private Long extApplicationTokenLifetime = null;


    private Long extUserTokenLifetime = null;


    private Long extRefreshTokenLifetime = null;


    private Long extIdTokenLifetime = null;


    private Boolean extPkceMandatory = null;


    private Boolean extPkceSupportPlain = null;


    private Boolean extPublicClient = null;

    private String tokenTypeExtension = null;
    private String extTokenType = null;


    private String jwksUri = null;
    private Boolean useClientIdAsSubClaimForAppTokens;
    private Boolean omitUsernameInIntrospectionRespForAppTokens;
    private String tokenEndpointAuthMethod = null;
    private Boolean tokenEndpointAllowReusePvtKeyJwt = null;
    private String tokenEndpointAuthSigningAlg = null;
    private String sectorIdentifierUri = null;
    private String idTokenSignedResponseAlg = null;
    private String idTokenEncryptedResponseAlg = null;
    private String idTokenEncryptedResponseEnc = null;
    private String requestObjectSigningAlg = null;
    private String tlsClientAuthSubjectDn = null;
    private Boolean requirePushAuthorizationRequest = null;
    private Boolean requireSignedRequestObject = null;
    private Boolean tlsClientCertificateBoundAccessToken = null;
    private String subjectType = null;
    private String requestObjectEncryptionAlgorithm = null;
    private String requestObjectEncryptionMethod = null;
    private String softwareStatement = null;
    private  Map<String, Object> additionalAttributes;
    private String extAllowedAudience;

  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("client_id")
  public String getClientId() {
    return clientId;
  }
  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("client_secret")
  public String getClientSecret() {
    return clientSecret;
  }
  public void setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
  }

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("client_secret_expires_at")
  public Long getClientSecretExpiresAt() {
    return clientSecretExpiresAt;
  }
  public void setClientSecretExpiresAt(Long clientSecretExpiresAt) {
    this.clientSecretExpiresAt = clientSecretExpiresAt;
  }

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("redirect_uris")
  public List<String> getRedirectUris() {
    return redirectUris;
  }
  public void setRedirectUris(List<String> redirectUris) {
    this.redirectUris = redirectUris;
  }

  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("grant_types")
  public List<String> getGrantTypes() {
    return grantTypes;
  }
  public void setGrantTypes(List<String> grantTypes) {
    this.grantTypes = grantTypes;
  }

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("client_name")
  public String getClientName() {
    return clientName;
  }
  public void setClientName(String clientName) {
    this.clientName = clientName;
  }

  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("ext_application_display_name")
  public String getExtApplicationDisplayName() {
    return extApplicationDisplayName;
  }
  public void setExtApplicationDisplayName(String extApplicationDisplayName) {
    this.extApplicationDisplayName = extApplicationDisplayName;
  }

    /**
    **/
    @ApiModelProperty(value = "")
    @JsonProperty("ext_application_owner")
    public String getExtApplicationOwner() {
        return extApplicationOwner;
    }
    public void setExtApplicationOwner(String extApplicationOwner) {
        this.extApplicationOwner = extApplicationOwner;
    }

    /**
    **/
    @ApiModelProperty(value = "")
    @JsonProperty("ext_application_token_lifetime")
    public Long getExtApplicationTokenLifetime() {
        return extApplicationTokenLifetime;
    }
    public void setExtApplicationTokenLifetime(Long extApplicationTokenLifetime) {
        this.extApplicationTokenLifetime = extApplicationTokenLifetime;
    }

    /**
    **/
    @ApiModelProperty(value = "")
    @JsonProperty("ext_user_token_lifetime")
    public Long getExtUserTokenLifetime() {
        return extUserTokenLifetime;
    }
    public void setExtUserTokenLifetime(Long extUserTokenLifetime) {
        this.extUserTokenLifetime = extUserTokenLifetime;
    }

    /**
    **/
    @ApiModelProperty(value = "")
    @JsonProperty("ext_refresh_token_lifetime")
    public Long getExtRefreshTokenLifetime() {
        return extRefreshTokenLifetime;
    }
    public void setExtRefreshTokenLifetime(Long extRefreshTokenLifetime) {
        this.extRefreshTokenLifetime = extRefreshTokenLifetime;
    }

    /**
    **/
    @ApiModelProperty(value = "")
    @JsonProperty("ext_id_token_lifetime")
    public Long getExtIdTokenLifetime() {
        return extIdTokenLifetime;
    }
    public void setExtIdTokenLifetime(Long extIdTokenLifetime) {
        this.extIdTokenLifetime = extIdTokenLifetime;
    }

    /**
    **/
    @ApiModelProperty(value = "")
    @JsonProperty("ext_pkce_mandatory")
    public Boolean getExtPkceMandatory() {
        return extPkceMandatory;
    }
    public void setExtPkceMandatory(Boolean extPkceMandatory) {
        this.extPkceMandatory = extPkceMandatory;
    }

    /**
    **/
    @ApiModelProperty(value = "")
    @JsonProperty("ext_pkce_support_plain")
    public Boolean getExtPkceSupportPlain() {
        return extPkceSupportPlain;
    }
    public void setExtPkceSupportPlain(Boolean extPkceSupportPlain) {
        this.extPkceSupportPlain = extPkceSupportPlain;
    }

    /**
    **/
    @ApiModelProperty(value = "")
    @JsonProperty("ext_public_client")
    public Boolean getExtPublicClient() {
        return extPublicClient;
    }
    public void setExtPublicClient(Boolean extPublicClient) {
        this.extPublicClient = extPublicClient;
    }

    /**
     **/
    @ApiModelProperty(value = "")
    @JsonProperty("token_type_extension")
    public String getTokenTypeExtension() {
      return tokenTypeExtension;
    }
    public void setTokenTypeExtension(String tokenType) {
      this.tokenTypeExtension = tokenType;
    }

    /**
     **/
    @ApiModelProperty(value = "")
    @JsonProperty("ext_token_type")
    public String getExtTokenType() {
      return extTokenType;
    }
    public void setExtTokenType(String tokenType) {
      this.extTokenType = tokenType;
    }

    /**
    **/
    @ApiModelProperty(value = "")
    @JsonProperty("jwks_uri")
    public String getJwksUri() {
        return jwksUri;
    }
    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
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

  public void setAdditionalAttributes(Map<String, Object> additionalAttributes) {
    this.additionalAttributes = additionalAttributes;
  }

  @JsonAnyGetter
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
  public String toString()  {
    StringBuilder sb = new StringBuilder();
    sb.append("class ApplicationDTO {\n");
    
    sb.append("  client_id: ").append(clientId).append("\n");
    sb.append("  client_secret: ").append(clientSecret).append("\n");
    sb.append("  client_secret_expires_at: ").append(clientSecretExpiresAt).append("\n");
    sb.append("  redirect_uris: ").append(redirectUris).append("\n");
    sb.append("  grant_types: ").append(grantTypes).append("\n");
    sb.append("  client_name: ").append(clientName).append("\n");
    sb.append("  extApplicationOwner: ").append(extApplicationOwner).append("\n");
    sb.append("  extApplicationTokenLifetime: ").append(extApplicationTokenLifetime).append("\n");
    sb.append("  extUserTokenLifetime: ").append(extUserTokenLifetime).append("\n");
    sb.append("  extRefreshTokenLifetime: ").append(extRefreshTokenLifetime).append("\n");
    sb.append("  extIdTokenLifetime: ").append(extIdTokenLifetime).append("\n");
    sb.append("  extPkceMandatory: ").append(extPkceMandatory).append("\n");
    sb.append("  extPkceSupportPlain: ").append(extPkceSupportPlain).append("\n");
    sb.append("  extPublicClient: ").append(extPublicClient).append("\n");
    sb.append("  jwksUri: ").append(jwksUri).append("\n");
    sb.append("  useClientIdAsSubClaimForAppTokens: ").append(useClientIdAsSubClaimForAppTokens).append("\n");
    sb.append("  omitUsernameInIntrospectionRespForAppTokens: ")
            .append(omitUsernameInIntrospectionRespForAppTokens).append("\n");
    sb.append("  tokenEndpointAuthMethod: ").append(tokenEndpointAuthMethod).append("\n");
    sb.append("  tokenEndpointAuthSigningAlg: ").append(tokenEndpointAuthSigningAlg).append("\n");
    sb.append("  sectorIdentifierUri: ").append(sectorIdentifierUri).append("\n");
    sb.append("  idTokenSignedResponseAlg: ").append(idTokenSignedResponseAlg).append("\n");
    sb.append("  idTokenEncryptedResponseAlg: ").append(idTokenEncryptedResponseAlg).append("\n");
    sb.append("  idTokenEncryptedResponseEnc: ").append(idTokenEncryptedResponseEnc).append("\n");
    sb.append("  requestObjectSigningAlg: ").append(requestObjectSigningAlg).append("\n");
    sb.append("  tlsClientAuthSubjectDn: ").append(tlsClientAuthSubjectDn).append("\n");
    sb.append("  requirePushAuthorizationRequest: ").append(requirePushAuthorizationRequest).append("\n");
    sb.append("  requireSignedRequestObject: ").append(requireSignedRequestObject).append("\n");
    sb.append("  tlsClientCertificateBoundAccessToken: ").append(tlsClientCertificateBoundAccessToken).append("\n");
    sb.append("  subjectType: ").append(subjectType).append("\n");
    sb.append("  requestObjectEncryptionAlgorithm: ").append(requestObjectEncryptionAlgorithm).append("\n");
    sb.append("  requestObjectEncryptionMethod: ").append(requestObjectEncryptionMethod).append("\n");
    sb.append("  softwareStatement: ").append(softwareStatement).append("\n");
    sb.append("  additionalAttributes: ").append(additionalAttributes).append("\n");
    sb.append("  extAllowedAudience: ").append(extAllowedAudience).append("\n");
        
    sb.append("}\n");
    return sb.toString();
  }
}
