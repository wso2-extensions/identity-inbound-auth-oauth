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

import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;
import org.wso2.carbon.identity.openidconnect.dao.RequestObjectPersistenceFactory;

import java.util.Map;

/**
 * This handler is used to invoke RequestObjectPersistenceFactory to persist OIDC request objects on different events.
 */
public class RequestObjectPersistanceHandler extends AbstractEventHandler {

    /**
     * Handles the event and invoke RequestObjectPersistenceFactory.
     * @param event event
     * @throws IdentityEventException
     */
    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        Map<String, Object> eventProperties = event.getEventProperties();
        String eventName = event.getEventName();
        String sessionDataKey = (String) eventProperties.get(OIDCConstants.Event.SESSION_DATA_KEY);

        if (OIDCConstants.Event.POST_ISSUE_CODE.equals(eventName)) {
            String codeId = (String) eventProperties.get(OIDCConstants.Event.CODE_ID);
            RequestObjectPersistenceFactory.getInstance().getRequestObjectDAO().updateRequestObjectReference
                    (sessionDataKey, codeId, null);

        } else if (OIDCConstants.Event.POST_ISSUE_ACCESS_TOKEN.equals(eventName)) {
            String tokenId = (String) eventProperties.get(OIDCConstants.Event.TOKEN_ID);
            RequestObjectPersistenceFactory.getInstance().getRequestObjectDAO().updateRequestObjectReference
                    (sessionDataKey, null, tokenId);
        }

    }

    public String getName() {
        return OIDCConstants.Event.PERSIST_REQUEST_OBJECT;
    }
}
