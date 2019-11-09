/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.token.bindings;

import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.oauth.common.token.bindings.TokenBinderInfo;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;

import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This interface represents the token binder API.
 */
public interface TokenBinder extends TokenBinderInfo {

    /**
     * Get or generate token binding value.
     *
     * @param request http servlet request.
     * @return token binding value.
     * @throws OAuthSystemException in case of failure.
     */
    String getOrGenerateTokenBindingValue(HttpServletRequest request) throws OAuthSystemException;

    /**
     * Get token binding value.
     *
     * @param oAuth2AccessTokenReqDTO OAuth2 access token request DTO.
     * @return token binding value optional.
     */
    Optional<String> getTokenBindingValue(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO);

    /**
     * Set token binding value for the response.
     *
     * @param response http servlet response.
     * @param bindingValue token binding value.
     */
    void setTokenBindingValueForResponse(HttpServletResponse response, String bindingValue);

    /**
     * Clear token binding elements.
     *
     * @param request http servlet request.
     * @param response http servlet response.
     */
    void clearTokenBindingElements(HttpServletRequest request, HttpServletResponse response);

    /**
     * Get validity of the token binding.
     *
     * @param request request object.
     * @param bindingReference token binding reference
     * @return true if token binding is valid.
     */
    boolean isValidTokenBinding(Object request, String bindingReference);
}
