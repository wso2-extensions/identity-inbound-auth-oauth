/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
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
package org.wso2.carbon.identity.oauth.endpoint.introspection;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

/**
 * this class is responsible for building the introspection response.
 */
public class IntrospectionResponseBuilder {

    private Map<String, Object> parameters = new HashMap<>();
    private boolean isActive = false;

    /**
     * build the introspection response.
     *
     * @return introspection response json string
     * @throws JSONException
     */
    public String build() throws JSONException {
        return JSONUtils.buildJSON(parameters);
    }

    /**
     * @param isActive whether token is in active state or not
     * @return IntrospectionResponseBuilder
     */
    public IntrospectionResponseBuilder setActive(boolean isActive) {
        parameters.put(IntrospectionResponse.ACTIVE, isActive);
        if (!isActive) {
            // if the token is not active we do not want to return back the expiration time.
            parameters.remove(IntrospectionResponse.EXP);
            // if the token is not active we do not want to return back the nbf time.
            parameters.remove(IntrospectionResponse.NBF);
        }
        this.isActive = isActive;
        return this;
    }

    /**
     * @param issuedAt token issued time
     * @return IntrospectionResponseBuilder
     */
    public IntrospectionResponseBuilder setIssuedAt(long issuedAt) {
        if (issuedAt != 0) {
            parameters.put(IntrospectionResponse.IAT, issuedAt);
        }
        return this;
    }

    /**
     * @param jwtId jwt ID
     * @return IntrospectionResponseBuilder
     */
    public IntrospectionResponseBuilder setJwtId(String jwtId) {
        if (StringUtils.isNotBlank(jwtId)) {
            parameters.put(IntrospectionResponse.JTI, jwtId);
        }
        return this;
    }

    /**
     * @param subject Subject
     * @return IntrospectionResponseBuilder
     */
    public IntrospectionResponseBuilder setSubject(String subject) {
        if (StringUtils.isNotBlank(subject)) {
            parameters.put(IntrospectionResponse.SUB, subject);
        }
        return this;
    }

    /**
     * @param expiration Token expiration time
     * @return IntrospectionResponseBuilder
     */
    public IntrospectionResponseBuilder setExpiration(long expiration) {
        if (isActive && expiration != 0) {
            // if the token is not active we do not want to return back the expiration time.
            parameters.put(IntrospectionResponse.EXP, expiration);
        }
        return this;
    }

    /**
     * @param username Username
     * @return IntrospectionResponseBuilder
     */
    public IntrospectionResponseBuilder setUsername(String username) {
        if (StringUtils.isNotBlank(username)) {
            parameters.put(IntrospectionResponse.USERNAME, username);
        }
        return this;
    }

    /**
     * @param tokenType Token type
     * @return IntrospectionResponseBuilder
     */
    public IntrospectionResponseBuilder setTokenType(String tokenType) {
        if (StringUtils.isNotBlank(tokenType)) {
            parameters.put(IntrospectionResponse.TOKEN_TYPE, tokenType);
        }
        return this;
    }

    /**
     * @param notBefore Not Before Time
     * @return IntrospectionResponseBuilder
     */
    public IntrospectionResponseBuilder setNotBefore(long notBefore) {
        if (isActive && notBefore != 0) {
            // if the token is not active we do not want to return back the nbf time.
            parameters.put(IntrospectionResponse.NBF, notBefore);
        }
        return this;
    }

    /**
     * @param audience Audience
     * @return IntrospectionResponseBuilder
     */
    public IntrospectionResponseBuilder setAudience(String audience) {
        if (StringUtils.isNotBlank(audience)) {
            parameters.put(IntrospectionResponse.AUD, audience);
        }
        return this;
    }

    /**
     * @param issuer Access token Issuer
     * @return IntrospectionResponseBuilder
     */
    public IntrospectionResponseBuilder setIssuer(String issuer) {
        if (StringUtils.isNotBlank(issuer)) {
            parameters.put(IntrospectionResponse.ISS, issuer);
        }
        return this;
    }

    /**
     * @param scope Scope
     * @return IntrospectionResponseBuilder
     */
    public IntrospectionResponseBuilder setScope(String scope) {
        if (StringUtils.isNotBlank(scope)) {
            parameters.put(IntrospectionResponse.SCOPE, scope);
        }
        return this;
    }

    /**
     * @param consumerKey Consumer Key
     * @return IntrospectionResponseBuilder
     */
    public IntrospectionResponseBuilder setClientId(String consumerKey) {
        if (StringUtils.isNotBlank(consumerKey)) {
            parameters.put(IntrospectionResponse.CLIENT_ID, consumerKey);
        }
        return this;
    }

    /**
     * @param errorCode Error Code
     * @return IntrospectionResponseBuilder
     */
    public IntrospectionResponseBuilder setErrorCode(String errorCode) {
        parameters.put(IntrospectionResponse.Error.ERROR, errorCode);
        return this;
    }

    /**
     * @param description Error Description
     * @return IntrospectionResponseBuilder
     */
    public IntrospectionResponseBuilder setErrorDescription(String description) {
        parameters.put(IntrospectionResponse.Error.ERROR_DESCRIPTION, description);
        return this;
    }

    public IntrospectionResponseBuilder setTokenBindingHash(String tokenBindingHash) {
        if (StringUtils.isNotBlank(tokenBindingHash)) {
            JSONObject tokenBindingHashJSONObject = new JSONObject();
            tokenBindingHashJSONObject.put(IntrospectionResponse.TBH, tokenBindingHash);
            parameters.put(IntrospectionResponse.CNF, tokenBindingHashJSONObject);

        }
        return this;
    }
}
