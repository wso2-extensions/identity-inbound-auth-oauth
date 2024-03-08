/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

import java.io.Serializable;

/**
 * This class is model class of a federated token.
 * A federated token is an external token obtained via an OIDC federated authenticator
 * after a successful authentication.
 */
public class FederatedTokenDO implements Serializable {

    private static final long serialVersionUID = 2717725650850067925L;
    private String idp;
    private String tokenValidityPeriod;
    private String scope;
    private String accessToken;
    private String refreshToken;

    // Constructor
    public FederatedTokenDO(String idp, String accessToken) {

        this.idp = idp;
        this.accessToken = accessToken;
    }

    // Getters and setters
    public String getIdp() {

        return idp;
    }

    public void setIdp(String idp) {

        this.idp = idp;
    }

    public String getTokenValidityPeriod() {

        return tokenValidityPeriod;
    }

    public void setTokenValidityPeriod(String tokenValidityPeriod) {

        this.tokenValidityPeriod = tokenValidityPeriod;
    }

    public String getScope() {

        return scope;
    }

    public void setScope(String scope) {

        this.scope = scope;
    }

    public String getAccessToken() {

        return accessToken;
    }

    public void setAccessToken(String accessToken) {

        this.accessToken = accessToken;
    }

    public String getRefreshToken() {

        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {

        this.refreshToken = refreshToken;
    }
}
