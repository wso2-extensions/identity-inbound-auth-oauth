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

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

import java.sql.Timestamp;
import java.util.Properties;

/**
 * Results holder for refresh token validation query.
 */
public class RefreshTokenValidationDataDO {

    private String refreshToken;
    private String tokenId;

    private String accessToken;

    private AuthenticatedUser authorizedUser;

    private String[] scope;

    private String refreshTokenState;

    private String grantType;

    private Timestamp issuedTime;

    private long validityPeriodInMillis;

    private String tokenBindingReference;

    private Timestamp accessTokenIssuedTime;

    private long accessTokenValidityInMillis;

    private AccessTokenExtendedAttributes accessTokenExtendedAttributes;

    private boolean isConsented;

    private Properties properties = new Properties();

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public AuthenticatedUser getAuthorizedUser() {
        return authorizedUser;
    }

    public void setAuthorizedUser(AuthenticatedUser authorizedUser) {
        this.authorizedUser = authorizedUser;
    }

    public String[] getScope() {
        return scope;
    }

    public void setScope(String[] scope) {
        this.scope = scope;
    }

    public String getRefreshTokenState() {
        return refreshTokenState;
    }

    public void setRefreshTokenState(String refreshTokenState) {
        this.refreshTokenState = refreshTokenState;
    }

    public long getValidityPeriodInMillis() {
        return validityPeriodInMillis;
    }

    public void setValidityPeriodInMillis(long validityPeriod) {
        this.validityPeriodInMillis = validityPeriod;
    }

    public Timestamp getIssuedTime() {
        return issuedTime;
    }

    public void setIssuedTime(Timestamp issuedTime) {
        this.issuedTime = issuedTime;
    }

    public String getTokenId() {
        return tokenId;
    }

    public void setTokenId(String tokenId) {
        this.tokenId = tokenId;
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getTokenBindingReference() {

        return tokenBindingReference;
    }

    public void setTokenBindingReference(String tokenBindingReference) {

        this.tokenBindingReference = tokenBindingReference;
    }

    public Timestamp getAccessTokenIssuedTime() {
        return accessTokenIssuedTime;
    }

    public void setAccessTokenIssuedTime(Timestamp accessTokenIssuedTime) {
        this.accessTokenIssuedTime = accessTokenIssuedTime;
    }

    public long getAccessTokenValidityInMillis() {
        return accessTokenValidityInMillis;
    }

    public void setAccessTokenValidityInMillis(long accessTokenValidityInMillis) {
        this.accessTokenValidityInMillis = accessTokenValidityInMillis;
    }

    public AccessTokenExtendedAttributes getAccessTokenExtendedAttributes() {

        return accessTokenExtendedAttributes;
    }

    public void setAccessTokenExtendedAttributes(
            AccessTokenExtendedAttributes accessTokenExtendedAttributes) {

        this.accessTokenExtendedAttributes = accessTokenExtendedAttributes;
    }

    public boolean isConsented() {

        return isConsented;
    }

    public void setConsented(boolean consented) {

        isConsented = consented;
    }

    public String getRefreshToken() {

        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {

        this.refreshToken = refreshToken;
    }

    public Properties getProperties() {

        return properties;
    }

    public void addProperty(Object propName, Object propValue) {

        properties.put(propName, propValue);
    }

    public Object getProperty(Object propName) {

        return properties.get(propName);
    }
}
