/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.model;

import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;

import java.sql.Timestamp;

public class AccessTokenDO extends CacheEntry {

    private static final long serialVersionUID = -8123522530178387354L;

    private String consumerKey;

    private AuthenticatedUser authzUser;

    private String[] scope;

    private String tokenState;

    private String refreshToken;

    private String tokenId;

    private String accessToken;

    private String authorizationCode;

    private String grantType;

    private Timestamp issuedTime;

    private Timestamp refreshTokenIssuedTime;

    private long validityPeriod;

    private long validityPeriodInMillis;

    private long refreshTokenValidityPeriod;

    private long refreshTokenValidityPeriodInMillis;

    private int tenantID = MultitenantConstants.SUPER_TENANT_ID;

    private String tokenType;

    public AccessTokenDO(String consumerKey, AuthenticatedUser authzUser, String[] scope, Timestamp issuedTime, Timestamp
            refreshTokenIssuedTime, long validityPeriodInMillis, long refreshTokenValidityPeriodInMillis, String
                                 tokenType) {
        this.consumerKey = consumerKey;
        this.authzUser = authzUser;
        this.scope = scope;
        this.issuedTime = issuedTime;
        this.refreshTokenIssuedTime = refreshTokenIssuedTime;
        this.validityPeriod = validityPeriodInMillis / 1000;
        this.validityPeriodInMillis = validityPeriodInMillis;
        this.refreshTokenValidityPeriod = refreshTokenValidityPeriodInMillis / 1000;
        this.refreshTokenValidityPeriodInMillis = refreshTokenValidityPeriodInMillis;
        this.tokenType = tokenType;
    }

    public AccessTokenDO(String consumerKey, AuthenticatedUser authzUser, String[] scope, Timestamp issuedTime, Timestamp
            refreshTokenIssuedTime, long validityPeriodInMillis, long refreshTokenValidityPeriodInMillis, String
                                 tokenType, String authorizationCode) {
        this(consumerKey, authzUser, scope, issuedTime, refreshTokenIssuedTime, validityPeriodInMillis,
                refreshTokenValidityPeriodInMillis, tokenType);
        this.authorizationCode = authorizationCode;
    }

    /**
     * Create a copy of the passed token DO object.
     *
     * @param tokenDO Original Token DO
     */
    public static AccessTokenDO clone(AccessTokenDO tokenDO) {

        AccessTokenDO newTokenDO =  new AccessTokenDO(
                tokenDO.getConsumerKey(),
                tokenDO.getAuthzUser(),
                tokenDO.getScope(),
                tokenDO.getIssuedTime(),
                tokenDO.getRefreshTokenIssuedTime(),
                tokenDO.getValidityPeriodInMillis(),
                tokenDO.getRefreshTokenValidityPeriodInMillis(),
                tokenDO.getTokenType()
        );
        newTokenDO.setTenantID(tokenDO.getTenantID());
        newTokenDO.setTokenState(tokenDO.getTokenState());
        newTokenDO.setRefreshToken(tokenDO.getRefreshToken());
        newTokenDO.setAccessToken(tokenDO.getAccessToken());
        newTokenDO.setTokenId(tokenDO.getTokenId());
        newTokenDO.setAuthorizationCode(tokenDO.getAuthorizationCode());
        newTokenDO.setGrantType(tokenDO.getGrantType());

        return newTokenDO;
    }

    public AccessTokenDO() {

    }

    public int getTenantID() {
        return tenantID;
    }

    public void setTenantID(int tenantID) {
        this.tenantID = tenantID;
    }

    public String getConsumerKey() {
        return consumerKey;
    }

    public void setConsumerKey(String consumerKey) {
        this.consumerKey = consumerKey;
    }

    public AuthenticatedUser getAuthzUser() {
        return authzUser;
    }

    public void setAuthzUser(AuthenticatedUser authzUser) {
        this.authzUser = authzUser;
    }

    public String[] getScope() {
        return scope;
    }

    public void setScope(String[] scope) {
        this.scope = scope;
    }

    public Timestamp getIssuedTime() {
        return issuedTime;
    }

    public void setIssuedTime(Timestamp issuedTime) {
        this.issuedTime = issuedTime;
    }

    public Timestamp getRefreshTokenIssuedTime() {
        return refreshTokenIssuedTime;
    }

    public void setRefreshTokenIssuedTime(Timestamp refreshTokenIssuedTime) {
        this.refreshTokenIssuedTime = refreshTokenIssuedTime;
    }

    public long getValidityPeriod() {
        return validityPeriod;
    }

    public void setValidityPeriod(long validityPeriod) {
        this.validityPeriod = validityPeriod;
        this.validityPeriodInMillis = validityPeriod * 1000;
    }

    public String getTokenState() {
        return tokenState;
    }

    public void setTokenState(String tokenState) {
        this.tokenState = tokenState;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public long getValidityPeriodInMillis() {
        return validityPeriodInMillis;
    }

    public void setValidityPeriodInMillis(long validityPeriodInMillis) {
        this.validityPeriodInMillis = validityPeriodInMillis;
        this.validityPeriod = validityPeriodInMillis / 1000;
    }

//    public long getRefreshTokenValidityPeriod() {
//        return refreshTokenValidityPeriod;
//    }

    public void setRefreshTokenValidityPeriod(long refreshTokenValidityPeriod) {
        this.refreshTokenValidityPeriod = refreshTokenValidityPeriod;
        this.refreshTokenValidityPeriodInMillis = refreshTokenValidityPeriod * 1000;
    }

    public long getRefreshTokenValidityPeriodInMillis() {
        return refreshTokenValidityPeriodInMillis;
    }

    public void setRefreshTokenValidityPeriodInMillis(long refreshTokenValidityPeriodInMillis) {
        this.refreshTokenValidityPeriodInMillis = refreshTokenValidityPeriodInMillis;
        this.refreshTokenValidityPeriod = refreshTokenValidityPeriodInMillis / 1000;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public String getTokenId() {
        return tokenId;
    }

    public void setTokenId(String tokenId) {
        this.tokenId = tokenId;
    }

    public String getAuthorizationCode() {
        return authorizationCode;
    }

    public void setAuthorizationCode(String authorizationCode) {
        this.authorizationCode = authorizationCode;
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }
}
