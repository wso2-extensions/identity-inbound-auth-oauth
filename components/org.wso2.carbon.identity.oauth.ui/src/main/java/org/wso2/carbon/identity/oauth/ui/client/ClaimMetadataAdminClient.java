/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.oauth.ui.client;

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.claim.metadata.mgt.stub.ClaimMetadataManagementServiceClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.stub.ClaimMetadataManagementServiceStub;
import org.wso2.carbon.identity.claim.metadata.mgt.stub.dto.ExternalClaimDTO;

import java.rmi.RemoteException;

/**
 * This class invokes the operations of ClaimMetadataManagementService.
 */
public class ClaimMetadataAdminClient {

    private static final Log log = LogFactory.getLog(ClaimMetadataAdminClient.class);
    public static final String CLAIM_METADATA_MANAGEMENT_SERVICE = "ClaimMetadataManagementService";
    private ClaimMetadataManagementServiceStub stub;

    /**
     * To intiate ClaimMetadataAdminClient
     *
     * @param cookie           For session management
     * @param backendServerURL URL of the back end server where ClaimManagementServiceStub is running.
     * @param configCtx        ConfigurationContext
     * @throws AxisFault if error occurs when instantiating the stub
     */
    public ClaimMetadataAdminClient(String cookie, String backendServerURL, ConfigurationContext configCtx) throws
            AxisFault {

        String serviceURL = backendServerURL + CLAIM_METADATA_MANAGEMENT_SERVICE;
        stub = new ClaimMetadataManagementServiceStub(configCtx, serviceURL);
        ServiceClient client = stub._getServiceClient();
        Options option = client.getOptions();
        option.setManageSession(true);
        option.setProperty(org.apache.axis2.transport.http.HTTPConstants.COOKIE_STRING, cookie);
    }

    /**
     * To get claims associated with oidc claim dialect.
     *
     * @param externalClaimDialect oidc claim dialect
     * @return array of claims which are associated with oidc claim dialect
     * @throws RemoteException
     * @throws ClaimMetadataManagementServiceClaimMetadataException
     */
    public ExternalClaimDTO[] getExternalClaims(String externalClaimDialect) throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {

        try {
            return stub.getExternalClaims(externalClaimDialect);
        } catch (RemoteException e) {
            log.error(e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error(e.getMessage(), e);
            throw e;
        }
    }

}
