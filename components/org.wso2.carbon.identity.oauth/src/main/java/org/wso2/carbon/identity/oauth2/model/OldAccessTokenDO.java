/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.model;

import java.sql.Timestamp;

/**
 * This is an implementation of AccessTokenDO.java . This class defines additional variables and operations.
 * variables authzUser, validityPeriod, refreshTokenValidityPeriod shadowed for usage of Audit table
 */
public class OldAccessTokenDO extends AccessTokenDO {

    private int consumerKeyId;

    private String authzUser;

    private int tenantId;

    private String userDomain;

    private String userType;

    private long validityPeriod;

    private long refreshTokenValidityPeriod;

    private String tokenScopeHash;

    private String tokenStateId;

    private String subjectIdentifier;

    private String accessTokenHash;

    private String refreshTokenHash;

    public void setConsumerKeyId(int consumerKeyId) {
        this.consumerKeyId = consumerKeyId;
    }

    public void setAuthzUser(String authzUser) {
        this.authzUser = authzUser;
    }

    public void setTenantId(int tenantId) {
        this.tenantId = tenantId;
    }

    public void setUserDomain(String userDomain) {
        this.userDomain = userDomain;
    }

    public void setUserType(String userType) {
        this.userType = userType;
    }

    public void setTimeCreated(Timestamp timeCreated) {
        setIssuedTime(timeCreated);
    }

    public void setRefreshTokenTimeCreated(Timestamp refreshTokenTimeCreated) {
        setRefreshTokenIssuedTime(refreshTokenTimeCreated);
    }

    public void setValdityPeriod(long valdityPeriod) {
        this.validityPeriod = valdityPeriod;
    }

    public void setRefreshTokenValidityPeriod(long refreshTokenValidityPeriod) {
        this.refreshTokenValidityPeriod = refreshTokenValidityPeriod;
    }

    public void setTokenScopeHash(String tokenScopeHash) {
        this.tokenScopeHash = tokenScopeHash;
    }

    public void setTokenStateId(String tokenStateId) {
        this.tokenStateId = tokenStateId;
    }

    public void setSubjectIdentifier(String subjectIdentifier) {
        this.subjectIdentifier = subjectIdentifier;
    }

    public void setAccessTokenHash(String accessTokenHash) {
        this.accessTokenHash = accessTokenHash;
    }

    public void setRefreshTokenHash(String refreshTokenHash) {
        this.refreshTokenHash = refreshTokenHash;
    }

    public int getConsumerKeyId() {
        return this.consumerKeyId;
    }

    public String getAuthzUserValue() {
        return authzUser;
    }

    public int getTenantId() {
        return this.tenantId;
    }

    public String getUserDomain() {
        return userDomain;
    }

    public String getUserType() {
        return userType;
    }

    public Timestamp getTimeCreated() {
        return getIssuedTime();
    }

    public Timestamp getRefreshTokenTimeCreated() {
        return getRefreshTokenIssuedTime();
    }

    public long getValdityPeriod() {
        return validityPeriod;
    }

    public long getRefreshTokenValidityPeriod() {
        return refreshTokenValidityPeriod;
    }

    public String getTokenScopeHash() {
        return tokenScopeHash;
    }

    public String getTokenStateId() {
        return tokenStateId;
    }

    public String getSubjectIdentifier() {
        return subjectIdentifier;
    }

    public String getAccessTokenHash() {
        return accessTokenHash;
    }

    public String getRefreshTokenHash() {
        return refreshTokenHash;
    }
}

