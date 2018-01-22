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

import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;
import org.wso2.carbon.identity.openidconnect.dao.RequestObjectPersistenceFactory;

import java.util.List;
import java.util.Map;

/**
 * This handler is used to invoke RequestObjectPersistenceFactory to revoke code or token from request object reference
 * table when code or token is revoked from the original tables.
 */
public class RequestObjectRevokeHandler extends AbstractEventHandler {

    /**
     * Handles the event and invoke RequestObjectPersistenceFactory.
     * @param event event
     * @throws IdentityEventException
     */
    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        Map<String, Object> eventProperties = event.getEventProperties();
        String eventName = event.getEventName();
        try {
            if (OIDCConstants.Event.POST_REVOKE_ACESS_TOKEN.equals(eventName)) {
                List<String> accessTokens = (List) eventProperties.get(OIDCConstants.Event.ACEESS_TOKENS);
                for (String accessToken : accessTokens) {
                    RequestObjectPersistenceFactory.getInstance().getRequestObjectDAO().deleteRequestObjectReference
                            (accessToken, null);
                }
            } else if (OIDCConstants.Event.POST_REVOKE_CODE.equals(eventName)) {
                List<AuthzCodeDO> authzcodes = (List<AuthzCodeDO>) eventProperties.get(OIDCConstants.Event.CODES);
                for (AuthzCodeDO authzCodeDO : authzcodes) {
                    RequestObjectPersistenceFactory.getInstance().getRequestObjectDAO().deleteRequestObjectReference
                            (null, authzCodeDO.getAuthzCodeId());
                }
            }
        } catch (IdentityOAuth2Exception e) {
            throw new IdentityEventException("Error while invoking request object factory.");
        } catch (IdentityOAuthAdminException e) {
            throw new IdentityEventException("Error while invoking request object factory.");
        }
    }

    public String getName() {
        return OIDCConstants.Event.REVOKE_REQUEST_OBJECT;
    }
}
