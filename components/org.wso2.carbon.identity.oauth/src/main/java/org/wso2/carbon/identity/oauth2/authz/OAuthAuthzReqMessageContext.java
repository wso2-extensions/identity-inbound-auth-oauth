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

package org.wso2.carbon.identity.oauth2.authz;

import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;

import java.util.Properties;

public class OAuthAuthzReqMessageContext {

    private OAuth2AuthorizeReqDTO authorizationReqDTO;

    private String[] approvedScope;

    private long validityPeriod;

    private long authorizationCodeValidityPeriod;

    private long accessTokenValidityPeriod;
    
    private long refreshTokenvalidityPeriod;
    
    private long accessTokenIssuedTime;
    
    private long refreshTokenIssuedTime;
    
    private long codeIssuedTime;


    private Properties properties = new Properties();

    public OAuthAuthzReqMessageContext(OAuth2AuthorizeReqDTO authorizationReqDTO) {
        this.authorizationReqDTO = authorizationReqDTO;
    }

    public OAuth2AuthorizeReqDTO getAuthorizationReqDTO() {
        return authorizationReqDTO;
    }

    public void setAuthorizationReqDTO(OAuth2AuthorizeReqDTO authorizationReqDTO) {
        this.authorizationReqDTO = authorizationReqDTO;
    }

    public String[] getApprovedScope() {
        return approvedScope;
    }

    public void setApprovedScope(String[] approvedScope) {
        this.approvedScope = approvedScope;
    }

    @Deprecated
    /**
     * @deprecated Avoid using this, use getAccessTokenValidityPeriod or getOAuthorizationCodeValidityPeriod instead
     */
    public long getValidityPeriod() {
        return validityPeriod;
    }

    @Deprecated
    /**
     * @deprecated Avoid using this, use setAccessTokenValidityPeriod or setOAuthorizationCodeValidityPeriod instead
     */
    public void setValidityPeriod(long validityPeriod) {
        this.validityPeriod = validityPeriod;
    }

    public long getAuthorizationCodeValidityPeriod() {
        return authorizationCodeValidityPeriod;
    }

    public void setAuthorizationCodeValidityPeriod(long oauthorizationCodeValidityPeriod) {
        this.authorizationCodeValidityPeriod = oauthorizationCodeValidityPeriod;
    }

    public long getAccessTokenValidityPeriod() {
        return accessTokenValidityPeriod;
    }

    public void setAccessTokenValidityPeriod(long accessTokenValidityPeriod) {
        this.accessTokenValidityPeriod = accessTokenValidityPeriod;
    }

    public void addProperty(Object propName, Object propValue) {
        properties.put(propName, propValue);
    }

    public Object getProperty(Object propName) {
        return properties.get(propName);
    }

    public long getRefreshTokenvalidityPeriod() {
	return refreshTokenvalidityPeriod;
    }

    public void setRefreshTokenvalidityPeriod(long refreshTokenvalidityPeriod) {
	this.refreshTokenvalidityPeriod = refreshTokenvalidityPeriod;
    }

    public long getAccessTokenIssuedTime() {
	return accessTokenIssuedTime;
    }

    public void setAccessTokenIssuedTime(long accessTokenIssuedTime) {
	this.accessTokenIssuedTime = accessTokenIssuedTime;
    }

    public long getRefreshTokenIssuedTime() {
	return refreshTokenIssuedTime;
    }

    public void setRefreshTokenIssuedTime(long refreshTokenIssuedTime) {
	this.refreshTokenIssuedTime = refreshTokenIssuedTime;
    }

    public long getCodeIssuedTime() {
	return codeIssuedTime;
    }

    public void setCodeIssuedTime(long codeIssuedTime) {
	this.codeIssuedTime = codeIssuedTime;
    }
}
