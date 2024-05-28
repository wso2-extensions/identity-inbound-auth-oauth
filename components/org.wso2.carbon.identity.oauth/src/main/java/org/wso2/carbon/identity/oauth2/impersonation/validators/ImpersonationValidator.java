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

package org.wso2.carbon.identity.oauth2.impersonation.validators;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationContext;

/**
 * The {@code ImpersonationValidator} interface defines the contract for classes that validate impersonation requests.
 */
public interface ImpersonationValidator {

    /**
     * Gets the priority of the impersonation validator.
     *
     * @return the priority of the impersonation validator
     */
    public int getPriority();

    /**
     * Gets the name of the impersonation validator.
     *
     * @return the name of the impersonation validator
     */
    public String getImpersonationValidatorName();

    /**
     * Validates an impersonation request based on the provided impersonation context.
     *
     * @param impersonationContext      the impersonation context containing information about the validation process
     * @return an {@code ImpersonationContext} object representing the validation context,
     *         including validation status and any validation failure details
     * @throws IdentityOAuth2Exception if an error occurs during impersonation request validation
     */
    public ImpersonationContext validateImpersonation(ImpersonationContext impersonationContext)
            throws IdentityOAuth2Exception;
}
