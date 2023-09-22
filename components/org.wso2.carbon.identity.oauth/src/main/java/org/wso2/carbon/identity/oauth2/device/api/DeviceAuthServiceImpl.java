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
import org.wso2.carbon.identity.oauth2.device.codegenerator.GenerateKeys;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;
import org.wso2.carbon.identity.oauth2.device.model.DeviceFlowDO;

import java.util.Optional;

/**
 * Service layer to talk with DAO.
 */
public class DeviceAuthServiceImpl implements DeviceAuthService {

    @Override
    public String generateDeviceResponse(String deviceCode, String userCode, long quantifier, String clientId,
                                         String scopes) throws IdentityOAuth2Exception {

        return DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().
                insertDeviceFlowParametersWithQuantifier(deviceCode, userCode, quantifier, clientId, scopes);
    }

    @Override
    @Deprecated
    public void generateDeviceResponse(String deviceCode, String userCode, String clientId, String scopes)
            throws IdentityOAuth2Exception {

        generateDeviceResponse(deviceCode, userCode, GenerateKeys.getCurrentQuantifier(), clientId, scopes);
    }

    @Override
    public DeviceFlowDO getDetailsByUserCode(String userCode) throws IdentityOAuth2Exception {

        return DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().getDetailsForUserCode(userCode);
    }

    @Override
    public void setAuthenticationStatus(String userCode) throws IdentityOAuth2Exception {

        DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().setAuthenticationStatus(userCode);
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
    public Optional<String> getDeviceCode(String userCode) throws IdentityOAuth2Exception {

        return DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().getDeviceCodeForUserCode(userCode);
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
