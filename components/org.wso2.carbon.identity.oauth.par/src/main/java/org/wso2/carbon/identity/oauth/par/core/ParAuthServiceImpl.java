/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.par.core;

import org.wso2.carbon.identity.oauth.par.common.ParConstants;
import org.wso2.carbon.identity.oauth.par.model.ParAuthResponseData;

import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Provides authentication services.
 */
public class ParAuthServiceImpl implements ParAuthService {

    @Override
    public ParAuthResponseData generateParAuthResponse(HttpServletResponse response, HttpServletRequest request) {

        String uuid = generateParReqUriUUID();
        long expiry = ParConstants.EXPIRES_IN_DEFAULT_VALUE_IN_SEC;

        ParAuthResponseData parAuthResponse = new ParAuthResponseData();
        parAuthResponse.setUuid(uuid);
        parAuthResponse.setExpityTime(expiry);

        return parAuthResponse;
    }

    /**
     * Returns a unique AuthCodeKey.
     *
     * @return String Returns random uuid.
     */
    private String generateParReqUriUUID() {

        return UUID.randomUUID().toString();
    }

}
