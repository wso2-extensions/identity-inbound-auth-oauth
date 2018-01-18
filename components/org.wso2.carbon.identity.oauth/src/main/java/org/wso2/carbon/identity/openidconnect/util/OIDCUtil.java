/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.openidconnect.util;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;

import java.util.HashMap;
import java.util.List;

/**
 * This class is used to define OIDC relate utility methods.
 */
public class OIDCUtil {

    /**
     * Uses to revoke access tokens from the request object related tables after token revocation
     * happens from access token related tables.
     *
     * @param acessTokenId
     * @throws IdentityOAuth2Exception
     */
    public static void postRevokeAccessToken(String acessTokenId, List<String> acessToken) throws IdentityOAuth2Exception {

        String eventName = null;
        HashMap<String, Object> properties = new HashMap<>();
        if (StringUtils.isNotBlank(acessTokenId)) {
            eventName = OIDCConstants.Event.POST_REVOKE_ACESS_TOKEN_BY_ID;
            properties.put(OIDCConstants.Event.TOKEN_ID, acessTokenId);
        } else if (CollectionUtils.isNotEmpty(acessToken)) {
            eventName = OIDCConstants.Event.POST_REVOKE_ACESS_TOKEN;
            properties.put(OIDCConstants.Event.ACEESS_TOKENS, acessToken);
        }
        handleRequestObjectPersistanceEvent(eventName, properties);
    }

    /**
     * Uses to revoke codes from the request object related tables after token revocation
     * happens from access token related tables.
     *
     * @param codeId code id
     * @throws IdentityOAuth2Exception
     */
    public static void postRevokeCode(String codeId, List<AuthzCodeDO> authzCodeDOs) throws IdentityOAuth2Exception {

        String eventName = null;
        HashMap<String, Object> properties = new HashMap<>();
        if (StringUtils.isNotBlank(codeId)) {
            eventName = OIDCConstants.Event.POST_REVOKE_CODE_BY_ID;
            properties.put(OIDCConstants.Event.CODE_ID, codeId);
        } else if (CollectionUtils.isNotEmpty(authzCodeDOs)) {
            eventName = OIDCConstants.Event.POST_REVOKE_CODE;
            properties.put(OIDCConstants.Event.CODES, authzCodeDOs);
        }

        handleRequestObjectPersistanceEvent(eventName, properties);
    }

    private static void handleRequestObjectPersistanceEvent(String eventName, HashMap<String, Object> properties) throws IdentityOAuth2Exception {

        try {
            if (StringUtils.isNotBlank(eventName)) {
                Event requestObjectPersistanceEvent = new Event(eventName, properties);
                if (OpenIDConnectServiceComponentHolder.getInstance().getIdentityEventService() != null) {
                    OpenIDConnectServiceComponentHolder.getInstance().getIdentityEventService().handleEvent
                            (requestObjectPersistanceEvent);
                }
            }
        } catch (IdentityEventException e) {
            throw new IdentityOAuth2Exception("Error while invoking the request object persistance handler.");
        }
    }
}
