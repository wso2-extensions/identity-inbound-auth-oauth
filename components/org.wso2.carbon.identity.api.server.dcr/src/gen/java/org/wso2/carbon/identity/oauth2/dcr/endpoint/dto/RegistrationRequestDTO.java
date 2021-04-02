package org.wso2.carbon.identity.oauth2.dcr.endpoint.dto;

import java.util.ArrayList;
import java.util.List;

import io.swagger.annotations.*;
import com.fasterxml.jackson.annotation.*;

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


  private String clientId = null;


  private String clientSecret = null;


  private List<String> contacts = new ArrayList<String>();


  private List<String> postLogoutRedirectUris = new ArrayList<String>();


  private List<String> requestUris = new ArrayList<String>();


  private List<String> responseTypes = new ArrayList<String>();


  private String spTemplateName = null;


  private String backchannelLogoutUri = null;


  private Boolean backchannelLogoutSessionRequired = null;


  private List<String> aud = new ArrayList<String>();


  private String idTokenEncryptedResponseAlg = null;


  private String idTokenEncryptedResponseEnc = null;


  private String tokenEndpointAuthMethod = null;


  private String softwareId = null;


  private String tokenType = null;


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
  @JsonProperty("ext_param_client_id")
  public String getClientId() {
    return clientId;
  }
  public void setClientId(String clientId) {
    this.clientId = clientId;
  }


  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("ext_param_client_secret")
  public String getClientSecret() {
    return clientSecret;
  }
  public void setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
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


  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("ext_param_sp_template")
  public String getSpTemplateName() {
    return spTemplateName;
  }
  public void setSpTemplateName(String spTemplateName) {
    this.spTemplateName = spTemplateName;
  }


  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("backchannel_logout_uri")
  public String getBackchannelLogoutUri() {
    return backchannelLogoutUri;
  }
  public void setBackchannelLogoutUri(String backchannelLogoutUri) {
    this.backchannelLogoutUri = backchannelLogoutUri;
  }


  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("backchannel_logout_session_required")
  public Boolean getBackchannelLogoutSessionRequired() {
    return backchannelLogoutSessionRequired;
  }
  public void setBackchannelLogoutSessionRequired(Boolean backchannelLogoutSessionRequired) {
    this.backchannelLogoutSessionRequired = backchannelLogoutSessionRequired;
  }


  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("aud")
  public List<String> getAud() {
    return aud;
  }
  public void setAud(List<String> aud) {
    this.aud = aud;
  }


  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("id_token_encrypted_response_alg")
  public String getIdTokenEncryptedResponseAlg() {
    return idTokenEncryptedResponseAlg;
  }
  public void setIdTokenEncryptedResponseAlg(String idTokenEncryptedResponseAlg) {
    this.idTokenEncryptedResponseAlg = idTokenEncryptedResponseAlg;
  }


  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("id_token_encrypted_response_enc")
  public String getIdTokenEncryptedResponseEnc() {
    return idTokenEncryptedResponseEnc;
  }
  public void setIdTokenEncryptedResponseEnc(String idTokenEncryptedResponseEnc) {
    this.idTokenEncryptedResponseEnc = idTokenEncryptedResponseEnc;
  }


  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("token_endpoint_auth_method")
  public String getTokenEndpointAuthMethod() {
    return tokenEndpointAuthMethod;
  }
  public void setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {
    this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
  }


  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("software_id")
  public String getSoftwareId() {
    return softwareId;
  }
  public void setSoftwareId(String softwareId) {
    this.softwareId = softwareId;
  }


  /**
   **/
  @ApiModelProperty(value = "")
  @JsonProperty("token_type_extension")
  public String getTokenType() {
    return tokenType;
  }
  public void setTokenType(String tokenType) {
    this.tokenType = tokenType;
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
    sb.append("  ext_param_client_id: ").append(clientId).append("\n");
    sb.append("  ext_param_client_secret: ").append(clientSecret).append("\n");
    sb.append("  contacts: ").append(contacts).append("\n");
    sb.append("  post_logout_redirect_uris: ").append(postLogoutRedirectUris).append("\n");
    sb.append("  request_uris: ").append(requestUris).append("\n");
    sb.append("  response_types: ").append(responseTypes).append("\n");
    sb.append("  token_type_extension: ").append(tokenType).append("\n");
    sb.append("  ext_param_sp_template: ").append(spTemplateName).append("\n");
    sb.append("  backchannel_logout_uri: ").append(backchannelLogoutUri).append("\n");
    sb.append("  backchannel_logout_session_required: ").append(backchannelLogoutSessionRequired).append("\n");
    sb.append("  aud: ").append(aud).append("\n");
    sb.append("  id_token_encrypted_response_alg: ").append(idTokenEncryptedResponseAlg).append("\n");
    sb.append("  id_token_encrypted_response_enc: ").append(idTokenEncryptedResponseEnc).append("\n");
    sb.append("  token_endpoint_auth_method: ").append(tokenEndpointAuthMethod).append("\n");
    sb.append("  software_id: ").append(softwareId).append("\n");
    sb.append("}\n");
    return sb.toString();
  }
}