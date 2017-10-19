/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.endpoint.user.impl.extension;

import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth.user.UserInfoResponseBuilder;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;

/**
 * This is just a test class with a private constructor which will cause IllegalAccess Exception while instantiating.
 */

public class TesUserInfoResponseBuilder implements UserInfoResponseBuilder {

    private TesUserInfoResponseBuilder() {
        // Do nothing
    }

    @Override
    public String getResponseString(OAuth2TokenValidationResponseDTO tokenResponse) throws UserInfoEndpointException,
            OAuthSystemException {
        return null;
    }
}
