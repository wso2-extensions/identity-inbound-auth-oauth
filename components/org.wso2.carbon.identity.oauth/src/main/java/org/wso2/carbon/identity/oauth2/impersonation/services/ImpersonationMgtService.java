/*
 *  Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.oauth2.impersonation.services;


import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationRequestDTO;

/**
 * Interface for Impersonation Management.
 */
public interface ImpersonationMgtService {

    /**
     * Validates an impersonation request based on the provided impersonation request DTO.
     *
     * @param impersonationRequestDTO the impersonation request DTO containing information about the request.
     * @return an {@code ImpersonationContext} object representing the validation context,
     *         including validation status and any validation failure details
     * @throws IdentityOAuth2Exception if an error occurs during impersonation request validation
     */
    public ImpersonationContext validateImpersonationRequest(ImpersonationRequestDTO impersonationRequestDTO)
            throws IdentityOAuth2Exception;
}
