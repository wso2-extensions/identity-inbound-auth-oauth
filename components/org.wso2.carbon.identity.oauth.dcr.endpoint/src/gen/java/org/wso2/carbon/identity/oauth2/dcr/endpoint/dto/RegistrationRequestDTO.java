package org.wso2.carbon.identity.oauth2.dcr.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

import java.util.ArrayList;
import java.util.List;
import javax.validation.constraints.NotNull;





@ApiModel(description = "")
public class RegistrationRequestDTO  {
  
  
  @NotNull
  private List<String> redirectUris = new ArrayList<String>();
  
  @NotNull
  private String clientName = null;
  

  private List<String> grantTypes = new ArrayList<String>();

  
  private String applicationType = null;
  
  
  private String jwksUri = null;
  
  
  private String url = null;
  
  
  private List<String> contacts = new ArrayList<String>();
  
  
  private List<String> postLogoutRedirectUris = new ArrayList<String>();
  
  
  private List<String> requestUris = new ArrayList<String>();
  
  
  private List<String> responseTypes = new ArrayList<String>();

  
  /**
   **/
  @ApiModelProperty(required = true, value = "")
  @JsonProperty("redirect_uris")
  public List<String> getRedirectUris() {
    return redirectUris;
  }
  public void setRedirectUris(List<String> redirectUris) {
    this.redirectUris = redirectUris;
  }

  
  /**
   **/
  @ApiModelProperty(required = true, value = "")
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

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("application_type")
  public String getApplicationType() {
    return applicationType;
  }
  public void setApplicationType(String applicationType) {
    this.applicationType = applicationType;
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

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("url")
  public String getUrl() {
    return url;
  }
  public void setUrl(String url) {
    this.url = url;
  }

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("contacts")
  public List<String> getContacts() {
    return contacts;
  }
  public void setContacts(List<String> contacts) {
    this.contacts = contacts;
  }

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("post_logout_redirect_uris")
  public List<String> getPostLogoutRedirectUris() {
    return postLogoutRedirectUris;
  }
  public void setPostLogoutRedirectUris(List<String> postLogoutRedirectUris) {
    this.postLogoutRedirectUris = postLogoutRedirectUris;
  }

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("request_uris")
  public List<String> getRequestUris() {
    return requestUris;
  }
  public void setRequestUris(List<String> requestUris) {
    this.requestUris = requestUris;
  }

  
  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("response_types")
  public List<String> getResponseTypes() {
    return responseTypes;
  }
  public void setResponseTypes(List<String> responseTypes) {
    this.responseTypes = responseTypes;
  }

  

  @Override
  public String toString()  {
    StringBuilder sb = new StringBuilder();
    sb.append("class RegistrationRequestDTO {\n");
    
    sb.append("  redirect_uris: ").append(redirectUris).append("\n");
    sb.append("  client_name: ").append(clientName).append("\n");
    sb.append("  grant_types: ").append(grantTypes).append("\n");
    sb.append("  application_type: ").append(applicationType).append("\n");
    sb.append("  jwks_uri: ").append(jwksUri).append("\n");
    sb.append("  url: ").append(url).append("\n");
    sb.append("  contacts: ").append(contacts).append("\n");
    sb.append("  post_logout_redirect_uris: ").append(postLogoutRedirectUris).append("\n");
    sb.append("  request_uris: ").append(requestUris).append("\n");
    sb.append("  response_types: ").append(responseTypes).append("\n");
    sb.append("}\n");
    return sb.toString();
  }
}
