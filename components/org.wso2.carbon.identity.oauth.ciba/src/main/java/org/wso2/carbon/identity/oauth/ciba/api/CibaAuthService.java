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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.api;

import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaClientException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeRequest;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeResponse;

/**
 * Provides authentication services.
 */
public interface CibaAuthService {

    /**
     * Accepts auth code request  and responds with auth code response.
     *
     * @param cibaAuthCodeRequest CIBA Authentication Request Data Transfer Object.
     * @return CibaAuthCodeResponse CIBA Authentication Response Data Transfer Object.
     * @throws CibaCoreException Core exception from CIBA module.
     * @throws CibaClientException Client exception from CIBA core component.
     */
    CibaAuthCodeResponse generateAuthCodeResponse(CibaAuthCodeRequest cibaAuthCodeRequest) throws CibaCoreException,
            CibaClientException;
}
