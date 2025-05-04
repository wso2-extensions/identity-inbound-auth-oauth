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

package org.wso2.carbon.identity.oauth2.finegrainedauthz.services;

import org.wso2.carbon.identity.oauth2.finegrainedauthz.exceptions.FineGrainedAuthzConfigMgtException;
import org.wso2.carbon.identity.oauth2.finegrainedauthz.models.FineGrainedAuthzConfig;

/**
 * Service interface for managing fine-grained authorization configurations.
 */
public interface FineGrainedAuthzConfigMgtService {

    /**
     * Retrieves the fine-grained authorization configuration for a given tenant domain.
     *
     * @param tenantDomain The domain of the tenant whose fine-grained authorization configuration is to be retrieved.
     * @return The fine-grained authorization configuration of the specified tenant.
     * @throws FineGrainedAuthzConfigMgtException If there is an error in retrieving the configuration.
     */
    public FineGrainedAuthzConfig getFineGrainedAuthzConfig(String tenantDomain)
            throws FineGrainedAuthzConfigMgtException;

    /**
     * Sets the fine-grained authorization configuration for a given tenant domain.
     *
     * @param fineGrainedAuthzConfig The fine-grained authorization configuration to be set.
     * @param tenantDomain           The domain of the tenant for which the configuration is to be set.
     * @throws FineGrainedAuthzConfigMgtException If there is an error in setting the configuration.
     */
    public void setFineGrainedAuthzConfig(FineGrainedAuthzConfig fineGrainedAuthzConfig, String tenantDomain)
            throws FineGrainedAuthzConfigMgtException;
}
