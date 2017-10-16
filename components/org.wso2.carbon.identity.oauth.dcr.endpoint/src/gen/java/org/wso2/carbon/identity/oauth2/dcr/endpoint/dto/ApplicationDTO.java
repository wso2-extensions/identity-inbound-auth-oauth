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
  
  
  private String clientName = null;

  
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
  @JsonProperty("client_name")
  public String getClientName() {
    return clientName;
  }
  public void setClientName(String clientName) {
    this.clientName = clientName;
  }

  

  @Override
  public String toString()  {
    StringBuilder sb = new StringBuilder();
    sb.append("class ApplicationDTO {\n");
    
    sb.append("  client_id: ").append(clientId).append("\n");
    sb.append("  client_secret: ").append(clientSecret).append("\n");
    sb.append("  client_secret_expires_at: ").append(clientSecretExpiresAt).append("\n");
    sb.append("  redirect_uris: ").append(redirectUris).append("\n");
    sb.append("  client_name: ").append(clientName).append("\n");
    sb.append("}\n");
    return sb.toString();
  }
}
