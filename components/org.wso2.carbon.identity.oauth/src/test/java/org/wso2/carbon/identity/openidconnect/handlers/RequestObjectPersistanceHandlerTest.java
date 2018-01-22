/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;

import java.util.HashMap;

/**
 * Unit tests for RequestObjectPersistanceHandler.
 */
@WithCarbonHome
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB",
        files = {"dbScripts/h2_with_application_and_token.sql", "dbScripts/identity.sql"})
public class RequestObjectPersistanceHandlerTest {

    RequestObjectPersistanceHandler requestObjectPersistanceHandler = new RequestObjectPersistanceHandler();

    @DataProvider(name = "requestObjectPersist")
    public Object[][] revokeAccessToken() {

        return new Object[][]{{OIDCConstants.Event.POST_ISSUE_ACCESS_TOKEN, "token1", "session2", OIDCConstants.Event.
                TOKEN_ID},
                {OIDCConstants.Event.POST_ISSUE_CODE, "token1", "session2", OIDCConstants.Event.CODE_ID},};
    }

    @Test(dataProvider = "requestObjectPersist")
    public void testHandleEvent(String eventName, String code, String sessionDataKey, String propertyName)
            throws IdentityEventException {

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(propertyName, code);
        properties.put(OIDCConstants.Event.SESSION_DATA_KEY, sessionDataKey);
        Event event = new Event(eventName, properties);
        requestObjectPersistanceHandler.handleEvent(event);
        Assert.assertEquals(event.getEventProperties().size(), 2);
        Assert.assertEquals(requestObjectPersistanceHandler.getName(), OIDCConstants.Event.PERSIST_REQUEST_OBJECT);
    }
}
