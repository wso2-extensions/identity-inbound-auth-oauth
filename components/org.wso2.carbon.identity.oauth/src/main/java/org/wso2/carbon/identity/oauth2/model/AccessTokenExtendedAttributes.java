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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;
import java.util.Map;

/**
 * This class is used to store the extended attributes of the access token.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class AccessTokenExtendedAttributes implements Serializable {

    private static final long serialVersionUID = -3043225645166013281L;
    @JsonIgnore
    private boolean isExtendedToken;
    //Initial value set to -2 to identity that script hasn't changed the refresh token validity time.
    private int refreshTokenValidityPeriod = -2;
    private Map<String, String> parameters;

    public AccessTokenExtendedAttributes() {}

    public AccessTokenExtendedAttributes(int refreshTokenValidityPeriod, Map<String, String> parameters,
                                         boolean isExtendedToken) {

        this.refreshTokenValidityPeriod = refreshTokenValidityPeriod;
        this.parameters = parameters;
        this.isExtendedToken = isExtendedToken;
    }

    public AccessTokenExtendedAttributes(int refreshTokenValidityPeriod, Map<String, String> parameters) {

        this.refreshTokenValidityPeriod = refreshTokenValidityPeriod;
        this.parameters = parameters;
    }

    public AccessTokenExtendedAttributes(Map<String, String> parameters) {

        this.isExtendedToken = true;
        this.parameters = parameters;
    }

    /**
     * This method is used to get the refresh token validity period.
     *
     * @return Validity period of the refresh token.
     */
    public int getRefreshTokenValidityPeriod() {

        return refreshTokenValidityPeriod;
    }

    /**
     * This method is used to set the refresh token validity period.
     *
     * @param refreshTokenValidityPeriod Validity period of the refresh token.
     */
    public void setRefreshTokenValidityPeriod(int refreshTokenValidityPeriod) {

        this.refreshTokenValidityPeriod = refreshTokenValidityPeriod;
    }

    /**
     * This method is used to get the parameters.
     *
     * @return Parameters of the access token.
     */
    public Map<String, String> getParameters() {

        return parameters;
    }

    /**
     * This method is used to set the parameters.
     *
     * @param parameters Parameters of the access token.
     */
    public void setParameters(Map<String, String> parameters) {

        this.parameters = parameters;
    }

    /**
     * This method is used to check whether the token is extended token.
     *
     * @return True if the token is extended token.
     */
    public boolean isExtendedToken() {

        return isExtendedToken;
    }

    /**
     * This method is used to set whether the token is extended token.
     *
     * @param isExtendedToken True if the token is extended token.
     */
    public void setExtendedToken(boolean isExtendedToken) {

        this.isExtendedToken = isExtendedToken;
    }
}
