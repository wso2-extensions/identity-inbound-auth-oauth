/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * you may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth.dcr.model;

import java.util.ArrayList;
import java.util.List;

/**
 * This class represents an OAuth application populated with necessary data.
 */
public class RegistrationResponseProfile {

    private String clientId;
    private String clientSecret;
    private String clientIdIssueAt;
    private String clientSecretExpiresAt;

    private String clientName;
    private List<String> redirectUrls = new ArrayList<>();
    private List<String> grantTypes = new ArrayList<>();

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientIdIssueAt() {
        return new java.util.Date().toString();
    }

    public void setClientIdIssueAt(String clientIdIssueAt) {
        this.clientIdIssueAt = clientIdIssueAt;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getClientSecretExpiresAt() {
        return clientSecretExpiresAt;
    }

    public void setClientSecretExpiresAt(String clientSecretExpiresAt) {
        this.clientSecretExpiresAt = clientSecretExpiresAt;
    }

    public List<String> getGrantTypes() {
        return grantTypes;
    }

    public void setGrantTypes(List<String> grantTypes) {
        this.grantTypes = grantTypes;
    }

    public List<String> getRedirectUrls() {
        return redirectUrls;
    }

    public void setRedirectUrls(List<String> redirectUrls) {
        this.redirectUrls = redirectUrls;
    }
}
