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

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.client.attestation.mgt.services.ClientAttestationService;

/**
 * Holder class for managing instances of Client Attestation related services.
 * This class follows the Singleton pattern to provide a single point of access
 * to instances of services like ClientAttestationService, ApplicationManagementService.
 */
public class ClientAttestationServiceHolder {

    // Service instances
    private static class ClientAttestationHolder {

        static final ClientAttestationService SERVICE = (ClientAttestationService)
                PrivilegedCarbonContext.getThreadLocalCarbonContext()
                        .getOSGiService(ClientAttestationService.class, null);
    }

    private static class ApplicationManagementHolder {

        static final ApplicationManagementService SERVICE = (ApplicationManagementService)
                PrivilegedCarbonContext.getThreadLocalCarbonContext()
                        .getOSGiService(ApplicationManagementService.class, null);
    }

    /**
     * Gets the instance of the Client Attestation Service.
     *
     * @return The Client Attestation Service instance.
     */
    public static ClientAttestationService getClientAttestationService() {

        if (ClientAttestationHolder.SERVICE == null) {
            throw new IllegalStateException("ClientAttestationService is not available from OSGI context.");
        }
        return ClientAttestationHolder.SERVICE;
    }

    /**
     * Gets the instance of the Application Management Service.
     *
     * @return The Application Management Service instance.
     */
    public static ApplicationManagementService getApplicationManagementService() {

        if (ApplicationManagementHolder.SERVICE == null) {
            throw new IllegalStateException("ApplicationManagementService is not available from OSGI context.");
        }
        return ApplicationManagementHolder.SERVICE;
    }
}
