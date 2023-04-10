package org.wso2.carbon.identity.oauth;

import org.wso2.carbon.identity.oauth.dto.OAuthAppRevocationRequestDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.xds.common.constant.XDSWrapper;

/**
 * This class is used to update the application.
 */
public class OauthXDSWrapper implements XDSWrapper {

    private String consumerKey;
    private String secretKey;
    private OAuthConsumerAppDTO oAuthConsumerAppDTO;
    private String username;
    private int tenantId;

    private String scope;
    private String[] claims;
    private ScopeDTO scopeDTO;
    private String[] deleteClaims;
    private String state;
    private OAuthAppRevocationRequestDTO oAuthAppRevocationRequestDTO;
    private String appName;
    private OAuthRevocationRequestDTO oAuthRevocationRequestDTO;

    public OauthXDSWrapper(OauthXDSWrapperBuilder builder) {
        this.consumerKey = builder.consumerKey;
        this.secretKey = builder.secretKey;
        this.oAuthConsumerAppDTO = builder.oAuthConsumerAppDTO;
        this.username = builder.username;
        this.tenantId = builder.tenantId;
        this.scope = builder.scope;
        this.claims = builder.claims;
        this.scopeDTO = builder.scopeDTO;
        this.deleteClaims = builder.deleteClaims;
        this.state = builder.state;
        this.oAuthAppRevocationRequestDTO = builder.oAuthAppRevocationRequestDTO;
        this.appName = builder.appName;
        this.oAuthRevocationRequestDTO = builder.oAuthRevocationRequestDTO;
    }

    public String getConsumerKey() {
        return consumerKey;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public OAuthConsumerAppDTO getoAuthConsumerAppDTO() {
        return oAuthConsumerAppDTO;
    }

    public String getUsername() {
        return username;
    }

    public int getTenantId() {
        return tenantId;
    }

    public String getScope() {
        return scope;
    }

    public String[] getClaims() {
        return claims;
    }

    public ScopeDTO getScopeDTOs() {
        return scopeDTO;
    }

    public String[] getDeleteClaims() {
        return deleteClaims;
    }

    public String getState() {
        return state;
    }

    public String getAppName() {
        return appName;
    }

    public OAuthRevocationRequestDTO getoAuthRevocationRequestDTO() {
        return oAuthRevocationRequestDTO;
    }

    public OAuthAppRevocationRequestDTO getoAuthAppRevocationRequestDTO() {
        return oAuthAppRevocationRequestDTO;
    }

    /**
     * Builder class for OauthXDSWrapper.
     */
    public static class OauthXDSWrapperBuilder {
        private String consumerKey;
        private String secretKey;
        private OAuthConsumerAppDTO oAuthConsumerAppDTO;
        private String username;
        private String scope;
        private String[] claims;
        private int tenantId;
        private ScopeDTO scopeDTO;
        private String[] deleteClaims;
        private String state;
        private String appName;
        private OAuthAppRevocationRequestDTO oAuthAppRevocationRequestDTO;
        private OAuthRevocationRequestDTO oAuthRevocationRequestDTO;

        public OauthXDSWrapperBuilder setConsumerKey(String consumerKey) {
            this.consumerKey = consumerKey;
            return this;
        }

        public OauthXDSWrapperBuilder setSecretKey(String secretKey) {
            this.secretKey = secretKey;
            return this;
        }

        public OauthXDSWrapperBuilder setOAuthConsumerAppDTO(OAuthConsumerAppDTO oAuthConsumerAppDTO) {
            this.oAuthConsumerAppDTO = oAuthConsumerAppDTO;
            return this;
        }

        public OauthXDSWrapperBuilder setUsername(String username) {
            this.username = username;
            return this;
        }

        public OauthXDSWrapperBuilder setTenantId(int tenantId) {
            this.tenantId = tenantId;
            return this;
        }

        public OauthXDSWrapperBuilder setScope(String scope) {
            this.scope = scope;
            return this;
        }

        public OauthXDSWrapperBuilder setClaims(String[] claims) {
            this.claims = claims;
            return this;
        }

        public OauthXDSWrapperBuilder setScopeDTO(ScopeDTO scopeDTO) {
            this.scopeDTO = scopeDTO;
            return this;
        }

        public OauthXDSWrapperBuilder setDeleteClaims(String[] deleteClaims) {
            this.deleteClaims = deleteClaims;
            return this;
        }

        public OauthXDSWrapperBuilder setState(String state) {
            this.state = state;
            return this;
        }

        public OauthXDSWrapperBuilder setOAuthAppRevocationRequestDTO(
                OAuthAppRevocationRequestDTO oAuthAppRevocationRequestDTO) {
            this.oAuthAppRevocationRequestDTO = oAuthAppRevocationRequestDTO;
            return this;
        }

        public OauthXDSWrapperBuilder setAppName(String appName) {
            this.appName = appName;
            return this;
        }

        public OauthXDSWrapperBuilder setOAuthRevocationRequestDTO(
                OAuthRevocationRequestDTO oAuthRevocationRequestDTO) {
            this.oAuthRevocationRequestDTO = oAuthRevocationRequestDTO;
            return this;
        }

        public OauthXDSWrapper build() {
            return new OauthXDSWrapper(this);
        }
    }
}
