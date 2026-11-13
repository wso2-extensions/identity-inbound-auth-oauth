/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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
package org.wso2.carbon.identity.oauth.dto;

import org.wso2.carbon.identity.oauth.common.OAuthConstants;

/**
 * Client secret response Data Transfer Object. Carries the details of a client secret returned to the service and
 * REST layers. The expiry time is Unix epoch seconds, where zero denotes a never-expiring secret.
 */
public class OAuthClientSecretResponseDTO {

    private String secretId;
    private String secretValue;
    private Long expiryTime;
    private Long createdTime;
    private OAuthConstants.ClientSecretStatus status;
    private boolean latest;

    public String getSecretId() {

        return secretId;
    }

    public void setSecretId(String secretId) {

        this.secretId = secretId;
    }

    public String getSecretValue() {

        return secretValue;
    }

    public void setSecretValue(String secretValue) {

        this.secretValue = secretValue;
    }

    public Long getExpiryTime() {

        return expiryTime;
    }

    public void setExpiryTime(Long expiryTime) {

        this.expiryTime = expiryTime;
    }

    public Long getCreatedTime() {

        return createdTime;
    }

    public void setCreatedTime(Long createdTime) {

        this.createdTime = createdTime;
    }

    public OAuthConstants.ClientSecretStatus getStatus() {

        return status;
    }

    public void setStatus(OAuthConstants.ClientSecretStatus status) {

        this.status = status;
    }

    public boolean isLatest() {

        return latest;
    }

    public void setLatest(boolean latest) {

        this.latest = latest;
    }
}
