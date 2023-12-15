/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.bindings.impl;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.oauth2.OAuth2Constants.TokenBinderType.CLIENT_REQUEST;


/**
 * Client Request binding to the token.
 */
public class ClientRequestTokenBinder extends AbstractTokenBinder {

    private static final String CLIENT_INSTANCE_REF = "tokenBindingReference";

    @Override
    public Optional<String> getTokenBindingValue(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO) {

        RequestParameter[] parameters = oAuth2AccessTokenReqDTO.getRequestParameters();
        for (RequestParameter parameter : parameters) {
            if (CLIENT_INSTANCE_REF.equals(parameter.getKey())
                    && StringUtils.isNotBlank(parameter.getValue()[0])) {
                        return Optional.ofNullable(parameter.getValue()[0]);
            }
        }
        return Optional.empty();
    }

    @Override
    public String getDisplayName() {

        return "Client Instance";
    }

    @Override
    public String getDescription() {

        return "Client Instance Token Binding";
    }

    @Override
    public String getBindingType() {

        return CLIENT_REQUEST;
    }

    @Override
    public List<String> getSupportedGrantTypes() {
        Set<String> supportedGrantTypes = OAuthServerConfiguration.getInstance().getSupportedGrantTypes().keySet();
        return supportedGrantTypes.stream().collect(Collectors.toList());
    }

    @Override
    public String getOrGenerateTokenBindingValue(HttpServletRequest request) {

        return null;
    }

    @Override
    public void setTokenBindingValueForResponse(HttpServletResponse response, String bindingValue) {

    }

    @Override
    public void clearTokenBindingElements(HttpServletRequest request, HttpServletResponse response) {

    }

    @Override
    public boolean isValidTokenBinding(Object request, String bindingReference) {

        /*
         * As the token binding reference is same as the device code, the token call implementation
         * will validate the device code. So no need to revalidate here.
         */
        return true;
    }

    @Override
    public boolean isValidTokenBinding(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO, String bindingReference) {

        /*
         * As the token binding reference is same as the device code, the token call implementation
         * will validate the device code. So no need to revalidate here.
         */
        return true;
    }
}
