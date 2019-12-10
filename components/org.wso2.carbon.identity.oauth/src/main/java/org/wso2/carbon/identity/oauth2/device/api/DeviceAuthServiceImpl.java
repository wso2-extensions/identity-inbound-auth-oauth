/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.device.api;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;

/**
 * Service layer to talk with DAO.
 */
public class DeviceAuthServiceImpl implements DeviceAuthService {

    @Override
    public void generateDeviceResponse(String deviceCode, String userCode, String clientId, String scopes)
            throws IdentityOAuth2Exception {

        DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().insertDeviceFlowParameters(deviceCode,
                userCode, clientId, Constants.EXPIRES_IN_VALUE, Constants.INTERVAL_VALUE, scopes);
    }

    @Override
    public void setAuthenticationStatus(String userCode) throws IdentityOAuth2Exception {

        DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().setAuthenticationStatus(userCode,
                Constants.USED);
    }

    @Override
    public void setCallbackUri(String clientId, String redirectURI) throws IdentityOAuth2Exception {

        DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().setCallbackURI(clientId, redirectURI);
    }

    @Override
    public String getClientId(String userCode) throws IdentityOAuth2Exception {

        return DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().getClientIdByUserCode(userCode);
    }

    @Override
    public String[] getScope(String userCode) throws IdentityOAuth2Exception {

        return DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().getScopesForUserCode(userCode);
    }

    @Override
    public String getStatus(String userCode) throws IdentityOAuth2Exception {

        return DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().getStatusForUserCode(userCode);
    }

    @Override
    public boolean validateClientInfo(String clientId) throws IdentityOAuth2Exception {

        return DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().checkClientIdExist(clientId);
    }
}
