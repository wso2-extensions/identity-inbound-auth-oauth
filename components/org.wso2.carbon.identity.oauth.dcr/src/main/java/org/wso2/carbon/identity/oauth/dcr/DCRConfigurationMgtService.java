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

package org.wso2.carbon.identity.oauth.dcr;

import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.model.DCRConfiguration;

/**
 * Service interface for managing the DCR configurations of a tenant.
 * This service is responsible for getting and setting the DCR configurations of a tenant.
 */
public interface DCRConfigurationMgtService {

    /**
     * Get the DCR configurations of a tenant.
     *
     * @return DCRConfiguration Returns an instance of {@code DCRConfiguration} belonging to the tenant.
     * @throws DCRMException
     */
    DCRConfiguration getDCRConfiguration() throws DCRMException;

    /**
     * Set the DCR configurations of a tenant.
     *
     * @param dcrConfigurationConfig The {@code DCRConfiguration} object to be set.
     * @throws DCRMException
     */
    void setDCRConfiguration(DCRConfiguration dcrConfigurationConfig) throws DCRMException;
}
