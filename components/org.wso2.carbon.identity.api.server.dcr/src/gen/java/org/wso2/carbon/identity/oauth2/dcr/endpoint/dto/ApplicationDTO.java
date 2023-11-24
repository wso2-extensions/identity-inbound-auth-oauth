package org.wso2.carbon.identity.oauth2.dcr.endpoint.dto;

import java.util.ArrayList;
import java.util.List;

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
  private String jwksUri = null;
  private String tokenEndpointAuthMethod = null;
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

  @ApiModelProperty
  @JsonProperty("jwks_uri")
  public String getJwksUri() {
    return jwksUri;
  }

  public void setJwksUri(String jwksUri) {
    this.jwksUri = jwksUri;
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
    sb.append("}\n");
    return sb.toString();
  }
}
