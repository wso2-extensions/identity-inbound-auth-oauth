/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.dto;

/**
 * OAuth 2 client application bean.
 */
public class OAuth2ClientApplicationDTO {

    private String consumerKey;
    private OAuth2TokenValidationResponseDTO accessTokenValidationResponse;

    /**
     * @return
     */
    public String getConsumerKey() {
        return consumerKey;
    }

    /**
     * @param consumerKey
     */
    public void setConsumerKey(String consumerKey) {
        this.consumerKey = consumerKey;
    }

    /**
     * @return
     */
    public OAuth2TokenValidationResponseDTO getAccessTokenValidationResponse() {
        return accessTokenValidationResponse;
    }

    /**
     * @param accessTokenValidationResponse
     */
    public void setAccessTokenValidationResponse(
            OAuth2TokenValidationResponseDTO accessTokenValidationResponse) {
        this.accessTokenValidationResponse = accessTokenValidationResponse;
    }

}
