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

package org.wso2.carbon.identity.oauth2.validators;

import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;

import java.util.Properties;

/**
 * OAuth 2 token validation message context.
 */
public class OAuth2TokenValidationMessageContext {

    OAuth2TokenValidationRequestDTO requestDTO;

    OAuth2TokenValidationResponseDTO responseDTO;

    Properties properties = new Properties();

    public OAuth2TokenValidationMessageContext(OAuth2TokenValidationRequestDTO requestDTO,
                                               OAuth2TokenValidationResponseDTO responseDTO) {
        this.requestDTO = requestDTO;
        this.responseDTO = responseDTO;
    }

    public OAuth2TokenValidationRequestDTO getRequestDTO() {
        return requestDTO;
    }

    public OAuth2TokenValidationResponseDTO getResponseDTO() {
        return responseDTO;
    }

    public Object addProperty(Object name, Object value) {
        return properties.put(name, value);
    }

    public Object getProperty(Object name) {
        return properties.get(name);
    }

}
