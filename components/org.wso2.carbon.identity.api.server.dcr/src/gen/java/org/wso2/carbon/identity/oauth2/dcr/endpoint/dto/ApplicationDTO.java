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

  
  private String extApplicationOwner = null;
  
  
  private Long extApplicationTokenLifetime = null;
  
  
  private Long extUserTokenLifetime = null;
  
  
  private Long extRefreshTokenLifetime = null;
  
  
  private Long extIdTokenLifetime = null;
  
  
  private Boolean pkceMandatory = null;
  
  
  private Boolean pkceSupportPlain = null;
  
  
  private Boolean bypassClientCredentials = null;

  
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
  public Boolean getPkceMandatory() {
    return pkceMandatory;
  }
  public void setPkceMandatory(Boolean pkceMandatory) {
    this.pkceMandatory = pkceMandatory;
  }

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("ext_pkce_support_plain")
  public Boolean getPkceSupportPlain() {
    return pkceSupportPlain;
  }
  public void setPkceSupportPlain(Boolean pkceSupportPlain) {
    this.pkceSupportPlain = pkceSupportPlain;
  }

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("ext_public_client")
  public Boolean getBypassClientCredentials() {
    return bypassClientCredentials;
  }
  public void setBypassClientCredentials(Boolean bypassClientCredentials) {
    this.bypassClientCredentials = bypassClientCredentials;
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
    sb.append("  ext_application_owner: ").append(extApplicationOwner).append("\n");
    sb.append("  ext_application_token_lifetime: ").append(extApplicationTokenLifetime).append("\n");
    sb.append("  ext_user_token_lifetime: ").append(extUserTokenLifetime).append("\n");
    sb.append("  ext_refresh_token_lifetime: ").append(extRefreshTokenLifetime).append("\n");
    sb.append("  ext_id_token_lifetime: ").append(extIdTokenLifetime).append("\n");
    sb.append("  ext_pkce_mandatory: ").append(pkceMandatory).append("\n");
    sb.append("  ext_pkce_support_plain: ").append(pkceSupportPlain).append("\n");
    sb.append("  ext_public_client: ").append(bypassClientCredentials).append("\n");
    sb.append("}\n");
    return sb.toString();
  }
}
