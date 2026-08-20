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

package org.wso2.carbon.identity.oauth.dao;

import java.io.Serializable;

/**
 * A client secret value and its expiry time, held on the OAuth application for authentication and export/import.
 */
public class OAuthConsumerSecretExpiryDO implements Serializable {

    private static final long serialVersionUID = 7846290135472086931L;

    private String secretValue;
    private Long expiryTime;

    public OAuthConsumerSecretExpiryDO() {

    }

    public OAuthConsumerSecretExpiryDO(String secretValue, Long expiryTime) {

        this.secretValue = secretValue;
        this.expiryTime = expiryTime;
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
}
