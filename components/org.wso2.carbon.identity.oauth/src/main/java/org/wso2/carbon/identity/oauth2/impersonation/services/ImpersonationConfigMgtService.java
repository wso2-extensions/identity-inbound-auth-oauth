/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.impersonation.services;

import org.wso2.carbon.identity.oauth2.impersonation.exceptions.ImpersonationConfigMgtException;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationConfig;

/**
 * Service interface for managing impersonation configurations.
 */
public interface ImpersonationConfigMgtService {

    /**
     * Retrieves the impersonation configuration for a given tenant domain.
     *
     * @param tenantDomain The domain of the tenant whose impersonation configuration is to be retrieved.
     * @return The impersonation configuration of the specified tenant.
     * @throws ImpersonationConfigMgtException If there is an error in retrieving the configuration.
     */
    public ImpersonationConfig getImpersonationConfig(String tenantDomain) throws ImpersonationConfigMgtException;

    /**
     * Sets the impersonation configuration for a given tenant domain.
     *
     * @param impersonationConfig The impersonation configuration to be set.
     * @param tenantDomain        The domain of the tenant for which the configuration is to be set.
     * @throws ImpersonationConfigMgtException If there is an error in setting the configuration.
     */
    public void setImpersonationConfig(ImpersonationConfig impersonationConfig, String tenantDomain)
            throws ImpersonationConfigMgtException;
}

