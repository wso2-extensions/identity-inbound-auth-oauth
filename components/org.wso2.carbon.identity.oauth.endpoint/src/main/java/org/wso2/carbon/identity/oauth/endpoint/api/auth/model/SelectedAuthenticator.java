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

import java.util.HashMap;
import java.util.Map;

/**
 * Class containing the selected authenticator.
 */
public class SelectedAuthenticator {

    private String authenticatorId;
    private Map<String, String> params = new HashMap<String, String>();

    public SelectedAuthenticator() {

    }

    public SelectedAuthenticator(String authenticatorId, Map<String, String> params) {

        this.authenticatorId = authenticatorId;
        this.params = params;
    }

    public String getAuthenticatorId() {

        return authenticatorId;
    }

    public void setAuthenticatorId(String authenticatorId) {

        this.authenticatorId = authenticatorId;
    }

    public Map<String, String> getParams() {

        return params;
    }

    public void setParams(Map<String, String> params) {

        this.params = params;
    }
}

