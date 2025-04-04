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

package org.wso2.carbon.identity.oauth2.dto;

import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetails;

import java.util.Properties;

/**
 * OAuth 2 authorize response DTO.
 */
public class OAuth2AuthorizeRespDTO {

    private String authorizationCode;
    private String accessToken;
    private String callbackURI;
    private String errorCode;
    private String errorMsg;
    private String tokenType;
    private String[] scope;
    private long validityPeriod;
    private String idToken;
    private Properties properties = new Properties();
    private String codeId;
    private String pkceCodeChallenge;
    private String pkceCodeChallengeMethod;
    private String oidcSessionId;
    private AuthorizationDetails authorizationDetails;

    private String subjectToken;
    public String getAuthorizationCode() {

        return authorizationCode;
    }

    public void setAuthorizationCode(String authorizationCode) {

        this.authorizationCode = authorizationCode;
    }

    public String getAccessToken() {

        return accessToken;
    }

    public void setAccessToken(String accessToken) {

        this.accessToken = accessToken;
    }

    public String getCallbackURI() {

        return callbackURI;
    }

    public void setCallbackURI(String callbackURI) {

        this.callbackURI = callbackURI;
    }

    public String getErrorCode() {

        return errorCode;
    }

    public void setErrorCode(String errorCode) {

        this.errorCode = errorCode;
    }

    public String getErrorMsg() {

        return errorMsg;
    }

    public void setErrorMsg(String errorMsg) {

        this.errorMsg = errorMsg;
    }

    public long getValidityPeriod() {

        return validityPeriod;
    }

    public void setValidityPeriod(long validityPeriod) {

        this.validityPeriod = validityPeriod;
    }

    public String[] getScope() {

        return scope;
    }

    public void setScope(String[] scope) {

        this.scope = scope;
    }

    public String getTokenType() {

        return tokenType;
    }

    public void setTokenType(String tokenType) {

        this.tokenType = tokenType;
    }

    public String getIdToken() {

        return idToken;
    }

    public void setIdToken(String idToken) {

        this.idToken = idToken;
    }

    public void addProperty(Object propName, Object propValue) {

        properties.put(propName, propValue);
    }

    public Object getProperty(Object propName) {

        return properties.get(propName);
    }

    public String getCodeId() {

        return codeId;
    }

    public void setCodeId(String codeId) {

        this.codeId = codeId;
    }

    public String getPkceCodeChallenge() {

        return pkceCodeChallenge;
    }

    public void setPkceCodeChallenge(String pkceCodeChallenge) {

        this.pkceCodeChallenge = pkceCodeChallenge;
    }

    public String getPkceCodeChallengeMethod() {

        return pkceCodeChallengeMethod;
    }

    public void setPkceCodeChallengeMethod(String pkceCodeChallengeMethod) {

        this.pkceCodeChallengeMethod = pkceCodeChallengeMethod;
    }

    /**
     * Set OIDC session Id value. This can be used to add sid claim into the id_token for the back channel logout.
     *
     * @param oidcSessionId OIDC session Id value.
     */
    public void setOidcSessionId(String oidcSessionId) {

        this.oidcSessionId = oidcSessionId;
    }

    /**
     *  Get OIDC session Id value.
     *
     * @return  OIDC session Id value.
     */
    public String getOidcSessionId() {

        return oidcSessionId;
    }

    public String getSubjectToken() {

        return subjectToken;
    }

    public void setSubjectToken(String subjectToken) {

        this.subjectToken = subjectToken;
    }

    /**
     * Retrieves the validated authorization details to be included in the authorize response.
     *
     * @return the {@link AuthorizationDetails} instance representing the validated authorization information.
     * If no authorization details are available, it will return {@code null}.
     */
    public AuthorizationDetails getAuthorizationDetails() {

        return this.authorizationDetails;
    }

    /**
     * Sets the authorization details.
     * This method sets {@link AuthorizationDetails} that can potentially be included in the authorization response.
     *
     * @param authorizationDetails the {@link AuthorizationDetails} to set.
     */
    public void setAuthorizationDetails(final AuthorizationDetails authorizationDetails) {

        this.authorizationDetails = authorizationDetails;
    }
}
