/*
 *  Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.client.attestation.filter;

import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.client.attestation.mgt.services.ClientAttestationService;

/**
 * Holder class for managing instances of Client Attestation related services.
 * This class follows the Singleton pattern to provide a single point of access
 * to instances of services like ClientAttestationService, ApplicationManagementService.
 */
public class ClientAttestationServiceHolder {

    // Singleton instance
    private static ClientAttestationServiceHolder instance = new ClientAttestationServiceHolder();

    // Service instances
    private ClientAttestationService clientAttestationService;
    private ApplicationManagementService applicationManagementService;
    // Private constructor to enforce Singleton pattern
    private ClientAttestationServiceHolder() {}

    /**
     * Returns the singleton instance of the ClientAttestationServiceHolder.
     *
     * @return The singleton instance.
     */
    public static ClientAttestationServiceHolder getInstance() {

        return instance;
    }

    /**
     * Gets the instance of the Client Attestation Service.
     *
     * @return The Client Attestation Service instance.
     */
    public ClientAttestationService getClientAttestationService() {

        return ClientAttestationServiceHolder.getInstance().clientAttestationService;
    }

    /**
     * Sets the instance of the Client Attestation Service.
     *
     * @param clientAttestationService The Client Attestation Service instance to set.
     */
    public void setClientAttestationService(ClientAttestationService clientAttestationService) {

        ClientAttestationServiceHolder.getInstance().clientAttestationService = clientAttestationService;
    }

    /**
     * Gets the instance of the Application Management Service.
     *
     * @return The Application Management Service instance.
     */
    public ApplicationManagementService getApplicationManagementService() {

        return ClientAttestationServiceHolder.getInstance().applicationManagementService;
    }

    /**
     * Sets the instance of the Application Management Service.
     *
     * @param applicationManagementService The Application Management Service instance to set.
     */
    public void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        ClientAttestationServiceHolder.getInstance().applicationManagementService = applicationManagementService;
    }
}
