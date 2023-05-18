package org.wso2.carbon.identity.oauth2.dcr.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

import java.util.ArrayList;
import java.util.List;
import javax.validation.constraints.NotNull;


@ApiModel
public class RegistrationRequestDTO  {

  @NotNull
  private List<String> redirectUris = new ArrayList<>();
  @NotNull
  private String clientName = null;
  private List<String> grantTypes = new ArrayList<>();
  private String applicationType = null;
  private String jwksUri = null;
  private String url = null;
  private String clientId = null;
  private String clientSecret = null;
  private List<String> contacts = new ArrayList<>();
  private List<String> postLogoutRedirectUris = new ArrayList<>();
  private List<String> requestUris = new ArrayList<>();
  private List<String> responseTypes = new ArrayList<>();
  private String tokenType = null;
  private String spTemplateName = null;
  private String backchannelLogoutUri = null;
  private boolean backchannelLogoutSessionRequired;
  private boolean isManagementApp;
  private String applicationDisplayName = null;
  private String tokenTypeExtension = null;
  private String extApplicationOwner = null;
  private Long extApplicationTokenLifetime = null;
  private Long extUserTokenLifetime = null;
  private Long extRefreshTokenLifetime = null;
  private Long extIdTokenLifetime = null;
  private String extParamClientId = null;
  private String extParamClientSecret = null;
  private String extParamSpTemplate = null;
  private Boolean pkceMandatory = null;
  private Boolean pkceSupportPlain = null;
  private Boolean bypassClientCredentials = null;
  

  @ApiModelProperty(required = true)
  @JsonProperty("redirect_uris")
  public List<String> getRedirectUris() {
    return redirectUris;
  }

  public void setRedirectUris(List<String> redirectUris) {
    this.redirectUris = redirectUris;
  }

  @ApiModelProperty(required = true)
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
  @JsonProperty("application_type")
  public String getApplicationType() {
    return applicationType;
  }

  public void setApplicationType(String applicationType) {
    this.applicationType = applicationType;
  }

  @ApiModelProperty
  @JsonProperty("jwks_uri")
  public String getJwksUri() {
    return jwksUri;
  }

  public void setJwksUri(String jwksUri) {
    this.jwksUri = jwksUri;
  }

  @ApiModelProperty
  @JsonProperty("url")
  public String getUrl() {
    return url;
  }

  public void setUrl(String url) {
    this.url = url;
  }

  @ApiModelProperty
  @JsonProperty("ext_param_client_id")
  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  @ApiModelProperty
  @JsonProperty("ext_param_client_secret")
  public String getClientSecret() {
    return clientSecret;
  }

  public void setClientSecret(String clientSecret) {
    this.clientSecret = clientSecret;
  }

  @ApiModelProperty
  @JsonProperty("contacts")
  public List<String> getContacts() {
    return contacts;
  }

  public void setContacts(List<String> contacts) {
    this.contacts = contacts;
  }

  @ApiModelProperty
  @JsonProperty("post_logout_redirect_uris")
  public List<String> getPostLogoutRedirectUris() {
    return postLogoutRedirectUris;
  }

  public void setPostLogoutRedirectUris(List<String> postLogoutRedirectUris) {
    this.postLogoutRedirectUris = postLogoutRedirectUris;
  }

  @ApiModelProperty
  @JsonProperty("request_uris")
  public List<String> getRequestUris() {
    return requestUris;
  }

  public void setRequestUris(List<String> requestUris) {
    this.requestUris = requestUris;
  }

  @ApiModelProperty
  @JsonProperty("response_types")
  public List<String> getResponseTypes() {
    return responseTypes;
  }

  public void setResponseTypes(List<String> responseTypes) {
    this.responseTypes = responseTypes;
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
  @JsonProperty("ext_param_sp_template")
  public String getSpTemplateName() {
    return spTemplateName;
  }

  public void setSpTemplateName(String spTemplateName) {
    this.spTemplateName = spTemplateName;
  }

  @ApiModelProperty
  @JsonProperty("is_management_app")
  public boolean isManagementApp() {

    return isManagementApp;
  }

  public void setManagementApp(boolean isManagementApp) {

    this.isManagementApp = isManagementApp;
  }

  @ApiModelProperty
  @JsonProperty("application_display_name")
  public String getApplicationDisplayName() {
    return applicationDisplayName;
  }
  public void setApplicationDisplayName(String applicationDisplayName) {
    this.applicationDisplayName = applicationDisplayName;
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
  @JsonProperty("pkce_mandatory")
  public Boolean getPkceMandatory() {
    return pkceMandatory;
  }
  public void setPkceMandatory(Boolean pkceMandatory) {
    this.pkceMandatory = pkceMandatory;
  }

  @ApiModelProperty(value = "")
  @JsonProperty("pkce_support_plain")
  public Boolean getPkceSupportPlain() {
    return pkceSupportPlain;
  }
  public void setPkceSupportPlain(Boolean pkceSupportPlain) {
    this.pkceSupportPlain = pkceSupportPlain;
  }

  @ApiModelProperty(value = "")
  @JsonProperty("bypass_client_credentials")
  public Boolean getBypassClientCredentials() {
    return bypassClientCredentials;
  }
  public void setBypassClientCredentials(Boolean bypassClientCredentials) {
    this.bypassClientCredentials = bypassClientCredentials;
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
    sb.append("  is_management_app: ").append(isManagementApp).append("\n");
    sb.append("  application_display_name: ").append(applicationDisplayName).append("\n");
    sb.append("  ext_application_owner: ").append(extApplicationOwner).append("\n");
    sb.append("  ext_application_token_lifetime: ").append(extApplicationTokenLifetime).append("\n");
    sb.append("  ext_user_token_lifetime: ").append(extUserTokenLifetime).append("\n");
    sb.append("  ext_refresh_token_lifetime: ").append(extRefreshTokenLifetime).append("\n");
    sb.append("  ext_id_token_lifetime: ").append(extIdTokenLifetime).append("\n");
    sb.append("  pkce_mandatory: ").append(pkceMandatory).append("\n");
    sb.append("  pkce_support_plain: ").append(pkceSupportPlain).append("\n");
    sb.append("  bypass_client_credentials: ").append(bypassClientCredentials).append("\n");
    sb.append("}\n");
    return sb.toString();
  }
}
