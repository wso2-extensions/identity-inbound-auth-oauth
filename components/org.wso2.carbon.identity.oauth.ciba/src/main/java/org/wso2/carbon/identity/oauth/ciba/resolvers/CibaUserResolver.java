/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth.ciba.resolvers;

import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaClientException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeRequest;

/**
 * Interface for resolving the user based on the authentication request.
 */
public interface CibaUserResolver {

    /**
     * Resolve the user based on the authentication request and returns the user’s subject identifier.
     *
     * @param cibaAuthCodeRequest Authentication request.
     * @return User’s “sub” claim.
     * @throws CibaCoreException   Error while validating the user.
     * @throws CibaClientException Error while validating the user.
     */
    String resolveUser(CibaAuthCodeRequest cibaAuthCodeRequest) throws CibaCoreException,
            CibaClientException;
}
