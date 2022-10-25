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

package org.wso2.carbon.identity.oauth2.token;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Oauth token request message context.
 */
public class OAuthTokenReqMessageContext {

    private OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO;

    private AuthenticatedUser authorizedUser;

    private String[] scope;

    private int tenantID;

    private long validityPeriod = OAuthConstants.UNASSIGNED_VALIDITY_PERIOD;

    private long refreshTokenvalidityPeriod = OAuthConstants.UNASSIGNED_VALIDITY_PERIOD;

    private long accessTokenIssuedTime;

    private long refreshTokenIssuedTime;

    private Properties properties = new Properties();

    private Map<String, Object> errorParameterMap;

    private TokenBinding tokenBinding;

    public OAuthTokenReqMessageContext(OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO) {

        this.oauth2AccessTokenReqDTO = oauth2AccessTokenReqDTO;
    }

    public OAuth2AccessTokenReqDTO getOauth2AccessTokenReqDTO() {

        return oauth2AccessTokenReqDTO;
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

    public int getTenantID() {

        return tenantID;
    }

    public void setTenantID(int tenantID) {

        this.tenantID = tenantID;
    }

    public long getValidityPeriod() {

        return validityPeriod;
    }

    public void setValidityPeriod(long validityPeriod) {

        this.validityPeriod = validityPeriod;
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

    public TokenBinding getTokenBinding() {

        return tokenBinding;
    }

    public void setTokenBinding(TokenBinding tokenBinding) {

        this.tokenBinding = tokenBinding;
    }

    /**
     * Get error parameter map
     *
     * @return The map of error parameters
     */
    public Map<String, Object> getErrorParameterMap() {

        return Collections.unmodifiableMap(getErrorMap());
    }

    /**
     * Add key values to error parameter map
     * @param key custom error key
     * @param value value of the corresponding key
     */
    public void addErrorParameter(String key, Object value) {

        getErrorMap().put(key, value);
    }

    /**
     * Get error parameter map
     *
     * @return the map of error parameter map is returned. A default map will be returned if values are not added to
     * the error parameter map
     */
    private Map<String, Object> getErrorMap() {

        if (errorParameterMap == null) {
            errorParameterMap = new HashMap<>();
        }
        return errorParameterMap;
    }

}
