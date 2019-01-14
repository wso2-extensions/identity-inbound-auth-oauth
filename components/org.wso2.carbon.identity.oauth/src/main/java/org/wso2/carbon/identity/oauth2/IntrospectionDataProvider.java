/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.oauth2;

import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;

import java.util.Map;

/**
 * This extension is to provide additional information for introspection response.
 */
public interface IntrospectionDataProvider {

    /**
     * Provide additional data for OAuth token introspection.
     *
     * @param oAuth2TokenValidationRequestDTO Token validation request DTO.
     * @param oAuth2IntrospectionResponseDTO Token introspection response DTO.
     * @return Map of additional data to be added to the introspection response.
     * @throws IdentityOAuth2Exception If an error occurs while setting additional introspection data.
     */
    Map<String, Object> getIntrospectionData(OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO,
                                             OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO) throws
            IdentityOAuth2Exception;
}
