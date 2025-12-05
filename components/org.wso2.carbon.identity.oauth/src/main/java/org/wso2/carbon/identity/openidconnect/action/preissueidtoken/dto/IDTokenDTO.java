/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openidconnect.action.preissueidtoken.dto;

import com.nimbusds.jwt.JWTClaimsSet;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

/**
 * Data Transfer Object for Pre-Issue ID Token Action.
 * Contains all attributes used in building an ID token.
 */
public class IDTokenDTO implements Serializable {

    private JWTClaimsSet idTokenClaimsSet;
    private List<String> audience;
    private Map<String, Object> customOIDCClaims;
    private long expiresIn;
    private boolean isPreIssueIDTokenActionExecuted;

    public JWTClaimsSet getIdTokenClaimsSet() {

        return idTokenClaimsSet;
    }

    public void setIdTokenClaimsSet(JWTClaimsSet idTokenClaimsSet) {

        this.idTokenClaimsSet = idTokenClaimsSet;
    }

    public List<String> getAudience() {

        return audience;
    }

    public void setAudience(List<String> audience) {

        this.audience = audience;
    }

    public long getExpiresIn() {

        return expiresIn;
    }

    public void setExpiresIn(long expiresIn) {

        this.expiresIn = expiresIn;
    }

    public boolean isPreIssueIDTokenActionExecuted() {

        return isPreIssueIDTokenActionExecuted;
    }

    public void setPreIssueIDTokenActionExecuted(boolean preIssueIDTokenActionExecuted) {

        isPreIssueIDTokenActionExecuted = preIssueIDTokenActionExecuted;
    }

    public Map<String, Object> getCustomOIDCClaims() {

        return customOIDCClaims;
    }

    public void setCustomOIDCClaims(Map<String, Object> customOIDCClaims) {

        this.customOIDCClaims = customOIDCClaims;
    }
}
