/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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

import org.wso2.carbon.identity.oauth.par.exceptions.ParCoreException;
import org.wso2.carbon.identity.oauth.par.model.ParAuthData;

import java.util.Map;

/**
 * Provides the PAR services.
 */
public interface ParAuthService {

    /**
     * Creates PAR AuthenticationResponse by setting the values for the response to be generated from PAR endpoint.
     *
     * @param parameters Map of parameters in the request.
     * @return Object that contains response data for request.
     */
    ParAuthData handleParAuthRequest(Map<String, String> parameters) throws ParCoreException;

    /**
     * Retrieves the parameter map relevant to the provided request_uri from store after validating.
     *
     * @param uuid     UUID of the request.
     * @param clientId Client ID of the request.
     * @return Parameter map for request.
     */
    Map<String, String> retrieveParams(String uuid, String clientId) throws ParCoreException;
}
