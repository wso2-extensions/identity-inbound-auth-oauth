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


    private String clientId = null;


    private String clientSecret = null;


    private List<String> grantTypes = new ArrayList<String>();


    private String backchannelLogoutUri = null;


    private Boolean backchannelLogoutSessionRequired = null;


    private String tokenType = null;


    private List<String> aud = new ArrayList<String>();


    private String idTokenEncryptionAlgorithm = null;


    private String idTokenEncryptionMethod = null;


    private String softwareId = null;




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
    @JsonProperty("token_type_extension")
    public String getTokenType() {
        return tokenType;
    }
    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
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
        sb.append("class UpdateRequestDTO {\n");

        sb.append("  redirect_uris: ").append(redirectUris).append("\n");
        sb.append("  client_name: ").append(clientName).append("\n");
        sb.append("  client_id: ").append(clientId).append("\n");
        sb.append("  client_secret: ").append(clientSecret).append("\n");
        sb.append("  grant_types: ").append(grantTypes).append("\n");
        sb.append("  backchannel_logout_uri: ").append(backchannelLogoutUri).append("\n");
        sb.append("  backchannel_logout_session_required: ").append(backchannelLogoutSessionRequired).append("\n");
        sb.append("  token_type_extension: ").append(tokenType).append("\n");
        sb.append("  aud: ").append(aud).append("\n");
        sb.append("  id_token_encrypted_response_alg: ").append(idTokenEncryptionAlgorithm).append("\n");
        sb.append("  id_token_encrypted_response_enc: ").append(idTokenEncryptionMethod).append("\n");
        sb.append("  software_id: ").append(softwareId).append("\n");
        sb.append("}\n");
        return sb.toString();
    }
}