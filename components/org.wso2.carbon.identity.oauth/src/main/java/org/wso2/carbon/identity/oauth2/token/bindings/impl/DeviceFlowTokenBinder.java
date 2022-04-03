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
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.oauth2.device.constants.Constants.DEVICE_FLOW_GRANT_TYPE;

/**
 * Device flow binder to bind the device code to the token.
 */
public class DeviceFlowTokenBinder extends AbstractTokenBinder {

    @Override
    public Optional<String> getTokenBindingValue(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO) {

        if (DEVICE_FLOW_GRANT_TYPE.equals(oAuth2AccessTokenReqDTO.getGrantType())) {
            RequestParameter[] parameters = oAuth2AccessTokenReqDTO.getRequestParameters();
            String deviceCode;
            for (RequestParameter parameter : parameters) {
                if (Constants.DEVICE_CODE.equals(parameter.getKey())
                        && StringUtils.isNotBlank(parameter.getValue()[0])) {
                    deviceCode = parameter.getValue()[0];
                    return Optional.ofNullable(deviceCode);
                }
            }
        } else {
            return super.getTokenBindingValue(oAuth2AccessTokenReqDTO);
        }
        return Optional.empty();
    }

    @Override
    public String getDisplayName() {

        return "Device Based";
    }

    @Override
    public String getDescription() {

        return "Bind token to the device. Supported grant type : " + DEVICE_FLOW_GRANT_TYPE;
    }

    @Override
    public String getBindingType() {

        return "device-flow";
    }

    @Override
    public List<String> getSupportedGrantTypes() {

        return Collections.singletonList(DEVICE_FLOW_GRANT_TYPE);
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
