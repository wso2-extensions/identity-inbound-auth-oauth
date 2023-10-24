/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.endpoint.api.auth.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Class containing authenticator details.
 */
public class Authenticator {

    private String authenticatorId;
    private String authenticator;
    private String idp;
    private AuthenticatorMetadata metadata;
    private List<String> requiredParams = new ArrayList<>();

    public Authenticator() {

    }

    public Authenticator(String authenticatorId, String authenticator, String idp, AuthenticatorMetadata metadata,
                         List<String> requiredParams) {

        this.authenticatorId = authenticatorId;
        this.authenticator = authenticator;
        this.idp = idp;
        this.metadata = metadata;
        this.requiredParams = requiredParams;
    }

    public String getAuthenticatorId() {

        return authenticatorId;
    }

    public void setAuthenticatorId(String authenticatorId) {

        this.authenticatorId = authenticatorId;
    }

    public String getAuthenticator() {

        return authenticator;
    }

    public void setAuthenticator(String authenticator) {

        this.authenticator = authenticator;
    }

    public String getIdp() {

        return idp;
    }

    public void setIdp(String idp) {

        this.idp = idp;
    }

    public AuthenticatorMetadata getMetadata() {

        return metadata;
    }

    public void setMetadata(AuthenticatorMetadata metadata) {

        this.metadata = metadata;
    }

    public List<String> getRequiredParams() {

        return requiredParams;
    }

    public void setRequiredParams(List<String> requiredParams) {

        this.requiredParams = requiredParams;
    }
}

