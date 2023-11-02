/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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
package org.wso2.carbon.identity.oauth2.responsemode.provider;

import org.apache.commons.lang.StringUtils;

import java.util.Set;

/**
 * An instance of this class can contain the authorization params of any success authorization flow.
 * If there is any error, SuccessResponseDTO inside the relevant AuthorizationResponseDTO is null
 */
public class SuccessResponseDTO {
    private String authorizationCode;
    private String idToken;
    private String accessToken;
    private String tokenType;
    private long validityPeriod;
    private String formPostBody;
    private Set<String> scope = null;

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

    public long getValidityPeriod() {

        return validityPeriod;
    }

    public void setValidityPeriod(long validityPeriod) {

        this.validityPeriod = validityPeriod;
    }

    public String getScope() {

        if (scope == null) {
            return null;
        }
        return StringUtils.join(scope, "+").trim();
    }

    public void setScope(Set<String> scope) {

        this.scope = scope;
    }

    public String getIdToken() {

        return idToken;
    }

    public void setIdToken(String idToken) {

        this.idToken = idToken;
    }

    public String getTokenType() {

        return tokenType;
    }

    public void setTokenType(String tokenType) {

        this.tokenType = tokenType;
    }

    public String getFormPostBody() {

        return formPostBody;
    }

    public void setFormPostBody(String formPostBody) {

        this.formPostBody = formPostBody;
    }
}
