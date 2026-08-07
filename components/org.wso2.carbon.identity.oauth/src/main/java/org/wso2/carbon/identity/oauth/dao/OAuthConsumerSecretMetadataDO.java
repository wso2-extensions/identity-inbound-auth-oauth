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
 * Client secret metadata cached with the OAuth application for authentication. Carries only the secret hash and
 * the expiry time, never the secret value, so it is safe to cache.
 */
public class OAuthConsumerSecretMetadataDO implements Serializable {

    private static final long serialVersionUID = -7842356918273645012L;

    private final String secretHash;
    private final Long expiryTime;

    public OAuthConsumerSecretMetadataDO(String secretHash, Long expiryTime) {

        this.secretHash = secretHash;
        this.expiryTime = expiryTime;
    }

    public String getSecretHash() {

        return secretHash;
    }

    public Long getExpiryTime() {

        return expiryTime;
    }
}
