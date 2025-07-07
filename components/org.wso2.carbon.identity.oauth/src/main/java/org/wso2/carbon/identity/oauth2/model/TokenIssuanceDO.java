/*
 *  Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.oauth2.model;

import org.wso2.carbon.identity.openidconnect.OIDCConstants;

/**
 * Data object to contain information related to token issuance.
 */
public class TokenIssuanceDO {

    private final String tokenId;
    private final String tokenType;
    private final String tenantDomain;
    private final String clientId;
    private final String grantType;
    private final OIDCConstants.TokenBillingCategory tokenBillingCategory;
    private final int appResidentTenantId;
    private final String issuedTime;
    private final String accessingOrganizationId;
    private final String issuerOrganizationId;

    private TokenIssuanceDO(Builder builder) {

        this.tokenId = builder.tokenId;
        this.tokenType = builder.tokenType;
        this.tenantDomain = builder.tenantDomain;
        this.clientId = builder.clientId;
        this.grantType = builder.grantType;
        this.tokenBillingCategory = builder.tokenBillingCategory;
        this.appResidentTenantId = builder.appResidentTenantId;
        this.issuedTime = builder.issuedTime;
        this.accessingOrganizationId = builder.accessingOrganizationId;
        this.issuerOrganizationId = builder.issuerOrganizationId;
    }

    public String getTokenId() {

        return tokenId;
    }

    public String getTokenType() {

        return tokenType;
    }

    public String getTenantDomain() {

        return tenantDomain;
    }

    public String getClientId() {

        return clientId;
    }

    public String getGrantType() {

        return grantType;
    }

    public OIDCConstants.TokenBillingCategory getTokenBillingCategory() {

        return tokenBillingCategory;
    }

    public int getAppResidentTenantId() {

        return appResidentTenantId;
    }

    public String getIssuedTime() {

        return issuedTime;
    }

    public String getAccessingOrganizationId() {

        return accessingOrganizationId;
    }

    public String getIssuerOrganizationId() {

        return issuerOrganizationId;
    }

    /**
     * Builder class for TokenIssuanceDO.
     */
    public static class Builder {

        private String tokenId;
        private String tokenType;
        private String tenantDomain;
        private String clientId;
        private String grantType;
        private OIDCConstants.TokenBillingCategory tokenBillingCategory;
        private int appResidentTenantId;
        private String issuedTime;
        private String accessingOrganizationId;
        private String issuerOrganizationId;

        public Builder tokenId(String tokenId) {

            this.tokenId = tokenId;
            return this;
        }

        public Builder tokenType(String tokenType) {

            this.tokenType = tokenType;
            return this;
        }

        public Builder tenantDomain(String tenantDomain) {

            this.tenantDomain = tenantDomain;
            return this;
        }

        public Builder clientId(String clientId) {

            this.clientId = clientId;
            return this;
        }

        public Builder grantType(String grantType) {

            this.grantType = grantType;
            return this;
        }

        public Builder tokenBillingCategory(OIDCConstants.TokenBillingCategory tokenCategory) {

            this.tokenBillingCategory = tokenCategory;
            return this;
        }

        public Builder appResidentTenantId(int appResidentTenantId) {

            this.appResidentTenantId = appResidentTenantId;
            return this;
        }

        public Builder issuedTime(String issuedTime) {

            this.issuedTime = issuedTime;
            return this;
        }

        public Builder issuerOrganizationId(String issuerOrganizationId) {

            this.issuerOrganizationId = issuerOrganizationId;
            return this;
        }

        public Builder accessingOrganization(String accessingOrganization) {

            this.accessingOrganizationId = accessingOrganization;
            return this;
        }

        public TokenIssuanceDO build() {

            return new TokenIssuanceDO(this);
        }
    }
}
