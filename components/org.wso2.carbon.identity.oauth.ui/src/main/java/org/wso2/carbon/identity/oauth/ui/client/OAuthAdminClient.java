/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ui.client;

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;

import org.wso2.carbon.identity.oauth.stub.OAuthAdminServiceStub;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthTokenExpiryTimeDTO;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthRevocationResponseDTO;

import java.rmi.RemoteException;

public class OAuthAdminClient {

    private static String[] allowedGrantTypes = null;
    private OAuthAdminServiceStub stub;
    /**
     * Instantiates OAuthAdminClient
     *
     * @param cookie           For session management
     * @param backendServerURL URL of the back end server where OAuthAdminService is running.
     * @param configCtx        ConfigurationContext
     * @throws org.apache.axis2.AxisFault
     */
    public OAuthAdminClient(String cookie, String backendServerURL, ConfigurationContext configCtx)
            throws AxisFault {
        String serviceURL = backendServerURL + "OAuthAdminService";
        stub = new OAuthAdminServiceStub(configCtx, serviceURL);
        ServiceClient client = stub._getServiceClient();
        Options option = client.getOptions();
        option.setManageSession(true);
        option.setProperty(org.apache.axis2.transport.http.HTTPConstants.COOKIE_STRING, cookie);
    }

    public OAuthConsumerAppDTO[] getAllOAuthApplicationData() throws Exception {
        return stub.getAllOAuthApplicationData();
    }

    public OAuthConsumerAppDTO getOAuthApplicationData(String consumerkey) throws Exception {
        return stub.getOAuthApplicationData(consumerkey);
    }

    public OAuthConsumerAppDTO getOAuthApplicationDataByAppName(String appName) throws Exception {
        return stub.getOAuthApplicationDataByAppName(appName);
    }


    // TODO : this method should return app data
    public void registerOAuthApplicationData(OAuthConsumerAppDTO application) throws Exception {
        stub.registerOAuthApplicationData(application);
    }

    // TODO : this method should be removed once above is done
    public OAuthConsumerAppDTO getOAuthApplicationDataByName(String applicationName) throws Exception {
        OAuthConsumerAppDTO[] dtos = stub.getAllOAuthApplicationData();
        if (dtos != null && dtos.length > 0) {
            for (OAuthConsumerAppDTO dto : dtos) {
                if (applicationName.equals(dto.getApplicationName())) {
                    return dto;
                }
            }
        }
        return null;

    }

    public void removeOAuthApplicationData(String consumerkey) throws Exception {
        stub.removeOAuthApplicationData(consumerkey);
    }

    public void updateOAuthApplicationData(OAuthConsumerAppDTO consumerAppDTO) throws Exception {
        stub.updateConsumerApplication(consumerAppDTO);
    }

    public OAuthConsumerAppDTO[] getAppsAuthorizedByUser() throws Exception {
        return stub.getAppsAuthorizedByUser();
    }

    public OAuthRevocationResponseDTO revokeAuthzForAppsByRessourceOwner(OAuthRevocationRequestDTO reqDTO) throws Exception {
        return stub.revokeAuthzForAppsByResoureOwner(reqDTO);
    }

    public boolean isPKCESupportedEnabled() throws Exception {
        return stub.isPKCESupportEnabled();
    }

    public String[] getAllowedOAuthGrantTypes() throws Exception {
        if (allowedGrantTypes == null) {
            allowedGrantTypes = stub.getAllowedGrantTypes();
        }
        return allowedGrantTypes;
    }

    public void regenerateSecretKey(String consumerkey) throws Exception {
        stub.updateOauthSecretKey(consumerkey);
    }

    public String getOauthApplicationState(String consumerKey) throws Exception {
        return stub.getOauthApplicationState(consumerKey);
    }

    public void updateOauthApplicationState(String consumerKey, String newState) throws Exception {
        stub.updateConsumerAppState(consumerKey, newState);
    }

    public OAuthTokenExpiryTimeDTO getOAuthTokenExpiryTimeDTO() throws RemoteException {
        return stub.getTokenExpiryTimes();
    }
}
