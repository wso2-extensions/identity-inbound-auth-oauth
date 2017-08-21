package org.wso2.carbon.identity.oauth2.dcr.endpoint.dto;

import java.util.ArrayList;
import java.util.List;

import io.swagger.annotations.*;
import com.fasterxml.jackson.annotation.*;

import javax.validation.constraints.NotNull;





@ApiModel(description = "")
public class UpdateRequestDTO  {
  
  
  
  private List<String> redirectUris = new ArrayList<String>();
  
  
  private String clientName = null;
  
  
  private List<String> grantTypes = new ArrayList<String>();

  
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

  

  @Override
  public String toString()  {
    StringBuilder sb = new StringBuilder();
    sb.append("class UpdateRequestDTO {\n");
    
    sb.append("  redirectUris: ").append(redirectUris).append("\n");
    sb.append("  clientName: ").append(clientName).append("\n");
    sb.append("  grantTypes: ").append(grantTypes).append("\n");
    sb.append("}\n");
    return sb.toString();
  }
}
