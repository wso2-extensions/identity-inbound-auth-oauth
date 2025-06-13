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

/**
 * Data object to contain information related to token issuance.
 */
public class TokenIssuanceDO {

    private String tokenId;
    private String tenantDomain;
    private String clientId;
    private String grantType;

    /**
     * Default constructor.
     */
    public TokenIssuanceDO(String tokenId, String tenantDomain, String clientId, String grantType) {
        this.tokenId = tokenId;
        this.tenantDomain = tenantDomain;
        this.clientId = clientId;
        this.grantType = grantType;
    }

    /**
     * Get the token ID.
     */
    public String getTokenId() {
        return tokenId;
    }

    /**
     * Set the token ID.
     */
    public void setTokenId(String tokenId) {
        this.tokenId = tokenId;
    }

    /**
     * Get the tenant domain.
     */
    public String getTenantDomain() {
        return tenantDomain;
    }

    /**
     * Set the tenant domain.
     */
    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }

    /**
     * Get the client ID.
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * Set the client ID.
     */
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    /**
     * Get the grant type.
     */
    public String getGrantType() {
        return grantType;
    }

    /**
     * Set the grant type.
     */
    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }
}
