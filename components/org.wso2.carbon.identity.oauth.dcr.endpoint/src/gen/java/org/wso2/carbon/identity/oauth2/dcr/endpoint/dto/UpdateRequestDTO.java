package org.wso2.carbon.identity.oauth2.dcr.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

import java.util.ArrayList;
import java.util.List;


@ApiModel
public class UpdateRequestDTO {

    private List<String> redirectUris = new ArrayList<>();
    private String clientName = null;
    private List<String> grantTypes = new ArrayList<>();
    private String tokenType = null;
    private String clientId = null;
    private String clientSecret = null;
    private String backchannelLogoutUri = null;
    private boolean backchannelLogoutSessionRequired;

    @ApiModelProperty
    @JsonProperty("redirect_uris")
    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(List<String> redirectUris) {
        this.redirectUris = redirectUris;
    }

    @ApiModelProperty
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
    @JsonProperty("token_type_extension")
    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    @JsonProperty("client_id")
    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    @ApiModelProperty
    @JsonProperty("client_secret")
    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
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

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("class UpdateRequestDTO {\n");

        sb.append("  redirect_uris: ").append(redirectUris).append("\n");
        sb.append("  client_name: ").append(clientName).append("\n");
        sb.append("  grant_types: ").append(grantTypes).append("\n");
        sb.append("  token_type_extension: ").append(tokenType).append("\n");
        sb.append("  client_id: ").append(clientId).append("\n");
        sb.append("  client_secret: ").append(clientSecret).append("\n");
        sb.append("  backchannel_logout_uri: ").append(backchannelLogoutUri).append("\n");
        sb.append("  backchannel_logout_session_required: ").append(backchannelLogoutSessionRequired).append("\n");
        sb.append("}\n");
        return sb.toString();
    }
}
