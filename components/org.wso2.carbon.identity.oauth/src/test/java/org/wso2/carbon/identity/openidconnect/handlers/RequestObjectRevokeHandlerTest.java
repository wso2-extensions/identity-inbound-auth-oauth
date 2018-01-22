/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.openidconnect.handlers;

import org.apache.commons.collections.CollectionUtils;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Unit Tests for RequestObjectRevokeHandler class.
 */
@WithCarbonHome
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB",
        files = {"dbScripts/h2_with_application_and_token.sql", "dbScripts/identity.sql"})
public class RequestObjectRevokeHandlerTest {

    RequestObjectRevokeHandler requestObjectRevokeHandler = new RequestObjectRevokeHandler();

    @DataProvider(name = "requestObjectRevoke")
    public Object[][] revokeAccessToken() {

        List<String> code = new ArrayList<>();
        code.add("code1");
        code.add("code2");
        AuthzCodeDO authzCodeDO = new AuthzCodeDO();
        authzCodeDO.setAuthorizationCode("code1");
        authzCodeDO.setAuthzCodeId("coded1");
        AuthzCodeDO authzCodeDO1 = new AuthzCodeDO();
        authzCodeDO1.setAuthzCodeId("codeId2");
        authzCodeDO1.setAuthorizationCode("code2");
        List<AuthzCodeDO> lstAuthzCode = new ArrayList<>();
        lstAuthzCode.add(authzCodeDO);
        lstAuthzCode.add(authzCodeDO1);
        return new Object[][]{{OIDCConstants.Event.POST_REVOKE_ACESS_TOKEN, code, null, OIDCConstants.Event.ACEESS_TOKENS},
                {OIDCConstants.Event.POST_REVOKE_CODE, null, lstAuthzCode, OIDCConstants.Event.CODES}};
    }

    @Test(dataProvider = "requestObjectRevoke")
    public void testHandleEvent(String eventName, List<String> code, List<AuthzCodeDO> lstAuthzCode, String propertyName)
            throws IdentityEventException {

        HashMap<String, Object> properties = new HashMap<>();
        if (CollectionUtils.isNotEmpty(code)) {
            properties.put(propertyName, code);
        } else if (CollectionUtils.isNotEmpty(lstAuthzCode)) {
            properties.put(propertyName, lstAuthzCode);
        }
        Event event = new Event(eventName, properties);
        requestObjectRevokeHandler.handleEvent(event);
        Assert.assertEquals(requestObjectRevokeHandler.getName(), OIDCConstants.Event.REVOKE_REQUEST_OBJECT);
        Assert.assertEquals(event.getEventProperties().size(), 1);
    }

}
