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
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Unit Tests for RequestObjectHandler class.
 */
@WithCarbonHome
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB",
        files = {"dbScripts/h2_with_application_and_token.sql", "dbScripts/identity.sql"})
public class RequestObjectHandlerTest {

    RequestObjectHandler requestObjectHandler = new RequestObjectHandler();

    @DataProvider(name = "requestObjectRevoke")
    public Object[][] revokeAccessToken() {

        List<String> codeList = new ArrayList<>();
        codeList.add("code1");
        codeList.add("code2");
        AuthzCodeDO authzCodeDO = new AuthzCodeDO();
        authzCodeDO.setAuthorizationCode("code1");
        authzCodeDO.setAuthzCodeId("coded1");
        AuthzCodeDO authzCodeDO1 = new AuthzCodeDO();
        authzCodeDO1.setAuthzCodeId("codeId2");
        authzCodeDO1.setAuthorizationCode("code2");
        List<AuthzCodeDO> lstAuthzCode = new ArrayList<>();
        lstAuthzCode.add(authzCodeDO);
        lstAuthzCode.add(authzCodeDO1);
        return new Object[][]{{OIDCConstants.Event.POST_REVOKE_ACESS_TOKEN, codeList, null, OIDCConstants.Event.
                ACEESS_TOKENS, null},
                {OIDCConstants.Event.POST_REVOKE_CODE, null, lstAuthzCode, OIDCConstants.Event.CODES, null},
                {OIDCConstants.Event.POST_ISSUE_ACCESS_TOKEN, null, null, OIDCConstants.Event.
                        TOKEN_ID, "token1"},
                {OIDCConstants.Event.POST_ISSUE_CODE, null, null, OIDCConstants.Event.
                        CODE_ID, "token1"}
        };
    }

    @Test(dataProvider = "requestObjectRevoke")
    public void testHandleEvent(String eventName, List<String> codeList, List<AuthzCodeDO> lstAuthzCode,
                                String propertyName, String code)
            throws IdentityEventException {

        HashMap<String, Object> properties = new HashMap<>();
        if (CollectionUtils.isNotEmpty(codeList)) {
            properties.put(propertyName, codeList);
        } else if (CollectionUtils.isNotEmpty(lstAuthzCode)) {
            properties.put(propertyName, lstAuthzCode);
        }
        properties.put(OIDCConstants.Event.TOKEN_STATE, OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED);
        properties.put(OIDCConstants.Event.SESSION_DATA_KEY, "sessionDataKey");
        properties.put(OIDCConstants.Event.NEW_ACCESS_TOKEN, "new");
        properties.put(OIDCConstants.Event.OLD_ACCESS_TOKEN, "old");
        Event event = new Event(eventName, properties);
        requestObjectHandler.handleEvent(event);
        Assert.assertEquals(requestObjectHandler.getName(), OIDCConstants.Event.HANDLE_REQUEST_OBJECT);
        Assert.assertNotNull(event.getEventProperties().size());
    }

}
