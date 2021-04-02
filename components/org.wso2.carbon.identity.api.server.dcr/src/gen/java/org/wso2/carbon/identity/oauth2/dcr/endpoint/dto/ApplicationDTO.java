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


  private String clientSecretExpiresAt = null;


  private List<String> redirectUris = new ArrayList<String>();


  private List<String> grantTypes = new ArrayList<String>();


  private String clientName = null;


  private  List<String> aud = new ArrayList<String>();


  private String tokenEndpointAuthMethod = null;


  private String idTokenEncryptionAlgorithm = null;


  private String idTokenEncryptionMethod = null;


  private String softwareId = null;


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
  public String getClientSecretExpiresAt() {
    return clientSecretExpiresAt;
  }
  public void setClientSecretExpiresAt(String clientSecretExpiresAt) {
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
  @JsonProperty("aud")
  public List<String> getAud() { return aud; }
  public void setAud(List<String> aud) {
    this.aud = aud;
  }

  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("token_endpoint_auth_method")
  public String getTokenEndpointAuthMethod() { return tokenEndpointAuthMethod; }
  public void setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {
    this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
  }

  /**
  **/
  @ApiModelProperty(value = "")
  @JsonProperty("id_token_encrypted_response_alg")
  public String getIdTokenEncryptionAlgorithm() { return idTokenEncryptionAlgorithm; }
  public void setIdTokenEncryptionAlgorithm(String idTokenEncryptionAlgorithm) {
    this.idTokenEncryptionAlgorithm = idTokenEncryptionAlgorithm;
  }

  /**
  **/
  @ApiModelProperty(value = "")
  @JsonProperty("id_token_encrypted_response_enc")
  public String getIdTokenEncryptionMethod() { return idTokenEncryptionMethod; }
  public void setIdTokenEncryptionMethod(String idTokenEncryptionMethod) {
    this.idTokenEncryptionMethod = idTokenEncryptionMethod;
  }

  /**
  **/
  @ApiModelProperty(value = "")
  @JsonProperty("software_id")
  public String getSoftwareId() { return softwareId; }
  public void setSoftwareId(String softwareId) {
    this.softwareId = softwareId;
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
    sb.append("  aud: ").append(aud).append("\n");
    sb.append("  token_endpoint_auth_method: ").append(tokenEndpointAuthMethod).append("\n");
    sb.append("  id_token_encrypted_response_alg: ").append(idTokenEncryptionAlgorithm).append("\n");
    sb.append("  id_token_encrypted_response_enc: ").append(idTokenEncryptionMethod).append("\n");
    sb.append("  software_id: ").append(softwareId).append("\n");
    sb.append("}\n");
    return sb.toString();
  }
}