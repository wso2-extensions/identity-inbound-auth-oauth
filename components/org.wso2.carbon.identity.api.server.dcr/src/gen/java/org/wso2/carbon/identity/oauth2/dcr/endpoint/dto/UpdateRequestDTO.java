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
    private String extApplicationDisplayName = null;
    private String extApplicationOwner = null;
    private Long extApplicationTokenLifetime = null;
    private Long extUserTokenLifetime = null;
    private Long extRefreshTokenLifetime = null;
    private Long extIdTokenLifetime = null;
    private boolean extPkceMandatory;
    private boolean extPkceSupportPlain;
    private boolean extPublicClient;

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

    @ApiModelProperty
    @JsonProperty("ext_application_display_name")
    public String getExtApplicationDisplayName() {
        return extApplicationDisplayName;
    }

    public void setExtApplicationDisplayName(String extApplicationDisplayName) {
        this.extApplicationDisplayName = extApplicationDisplayName;
    }

    @ApiModelProperty
    @JsonProperty("extApplicationOwner")
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
    @JsonProperty("ext_pkce_mandatory")
    public boolean getExtPkceMandatory() {
        return extPkceMandatory;
    }

    public void setExtPkceMandatory(boolean extPkceMandatory) {
        this.extPkceMandatory = extPkceMandatory;
    }

    @ApiModelProperty
    @JsonProperty("ext_pkce_support_plain")
    public boolean getExtPkceSupportPlain() {
        return extPkceSupportPlain;
    }

    public void setExtPkceSupportPlain(boolean extPkceSupportPlain) {
        this.extPkceSupportPlain = extPkceSupportPlain;
    }

    @ApiModelProperty
    @JsonProperty("ext_public_client")
    public boolean getExtPublicClient() {
        return extPublicClient;
    }

    public void setExtPublicClient(boolean extPublicClient) {
        this.extPublicClient = extPublicClient;
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
        sb.append("  ext_application_display_name: ").append(extApplicationDisplayName).append("\n");
        sb.append("  ext_application_owner: ").append(extApplicationOwner).append("\n");
        sb.append("  ext_application_token_lifetime: ").append(extApplicationTokenLifetime).append("\n");
        sb.append("  ext_user_token_lifetime: ").append(extUserTokenLifetime).append("\n");
        sb.append("  ext_refresh_token_lifetime: ").append(extRefreshTokenLifetime).append("\n");
        sb.append("  ext_id_token_lifetime: ").append(extIdTokenLifetime).append("\n");
        sb.append("  ext_pkce_mandatory: ").append(extPkceMandatory).append("\n");
        sb.append("  ext_pkce_support_plain: ").append(extPkceSupportPlain).append("\n");
        sb.append("  ext_public_client: ").append(extPublicClient).append("\n");
        sb.append("}\n");
        return sb.toString();
    }
}
