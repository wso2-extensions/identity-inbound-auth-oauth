/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openidconnect;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.openidconnect.cache.OIDCScopeClaimCache;

import java.util.Map;

/**
 * This handles the claim metadata operation related events and it will clear the OIDCScopeClaimCache
 * cache when the event is triggered. When these relevant events are fired the cache will be
 * cleared based on the tenant and the cache will be rebuilt with the next request.
 */
public class OIDCClaimMetaDataOperationHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(OIDCClaimMetaDataOperationHandler.class);
    private final OIDCScopeClaimCache oidcScopeClaimCache = OIDCScopeClaimCache.getInstance();
    private static final String HANDLER_NAME = "OIDCClaimMetaDataOperationHandler";

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        String eventName = event.getEventName();
        if (IdentityEventConstants.Event.POST_DELETE_EXTERNAL_CLAIM.equals(eventName)) {
            if (log.isDebugEnabled()) {
                log.debug("OIDCClaimMetaDataOperationHandler will not be executed for event: " + eventName);
            }
        }
        Map<String, Object> eventProperties = event.getEventProperties();
        if (MapUtils.isEmpty(eventProperties)) {
            return;
        }
        if (eventProperties.get(IdentityEventConstants.EventProperty.TENANT_ID) == null) {
            return;
        }
        int tenantId = (int) eventProperties.get(IdentityEventConstants.EventProperty.TENANT_ID);
        oidcScopeClaimCache.clearScopeClaimMap(tenantId);
    }

    @Override
    public String getName() {

        return HANDLER_NAME;
    }
}
