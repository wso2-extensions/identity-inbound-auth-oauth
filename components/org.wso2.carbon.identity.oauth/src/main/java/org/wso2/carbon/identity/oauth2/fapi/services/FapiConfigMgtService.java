/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2.fapi.services;

import org.wso2.carbon.identity.oauth2.fapi.exceptions.FapiConfigMgtException;
import org.wso2.carbon.identity.oauth2.fapi.models.FapiConfig;

/**
 * Service interface for managing Financial-grade API (FAPI) configurations.
 */
public interface FapiConfigMgtService {

    /**
     * Retrieves the FAPI configuration for a given tenant domain.
     *
     * @param tenantDomain The domain of the tenant whose FAPI configuration is to be retrieved.
     * @return The FAPI configuration of the specified tenant.
     * @throws FapiConfigMgtException If there is an error in retrieving the configuration.
     */
    FapiConfig getFapiConfig(String tenantDomain) throws FapiConfigMgtException;

    /**
     * Sets the FAPI configuration for a given tenant domain.
     *
     * @param fapiConfig   The FAPI configuration to be set.
     * @param tenantDomain The domain of the tenant for which the configuration is to be set.
     * @throws FapiConfigMgtException If there is an error in setting the configuration.
     */
    void setFapiConfig(FapiConfig fapiConfig, String tenantDomain) throws FapiConfigMgtException;
}
