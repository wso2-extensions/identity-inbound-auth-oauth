/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.oauth;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;

import java.util.HashMap;
import java.util.Map;

/**
 * This class handles creating event and publishing events related to scope management.
 */
public class OAuthScopeEventPublisherProxy {

    private static final Log log = LogFactory.getLog(OAuthScopeEventPublisherProxy.class);
    private static final OAuthScopeEventPublisherProxy proxy = new OAuthScopeEventPublisherProxy();

    private OAuthScopeEventPublisherProxy() {

    }

    public static OAuthScopeEventPublisherProxy getInstance() {

        return proxy;
    }

    public void publishPreAddScope(int tenantId, ScopeDTO scope) {

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.TENANT_ID, tenantId);
        eventProperties.put(IdentityEventConstants.EventProperty.SCOPE_NAME, scope.getName());
        eventProperties.put(IdentityEventConstants.EventProperty.SCOPE_DESCRIPTION, scope.getDescription());
        eventProperties.put(IdentityEventConstants.EventProperty.SCOPE_DISPLAY_NAME, scope.getDisplayName());
        eventProperties.put(IdentityEventConstants.EventProperty.SCOPE_CLAIMS, scope.getClaim());

        Event event = createEvent(eventProperties, IdentityEventConstants.Event.PRE_ADD_SCOPE);
        doPublishEvent(event);
    }

    public void publishPostAddScope(int tenantId, ScopeDTO scope) {

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.TENANT_ID, tenantId);
        eventProperties.put(IdentityEventConstants.EventProperty.SCOPE_NAME, scope.getName());
        eventProperties.put(IdentityEventConstants.EventProperty.SCOPE_DESCRIPTION, scope.getDescription());
        eventProperties.put(IdentityEventConstants.EventProperty.SCOPE_DISPLAY_NAME, scope.getDisplayName());
        eventProperties.put(IdentityEventConstants.EventProperty.SCOPE_CLAIMS, scope.getClaim());

        Event event = createEvent(eventProperties, IdentityEventConstants.Event.POST_ADD_SCOPE);
        doPublishEvent(event);
    }

    public void publishPreUpdateScope(int tenantId, ScopeDTO scope) {

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.TENANT_ID, tenantId);
        eventProperties.put(IdentityEventConstants.EventProperty.SCOPE_NAME, scope.getName());
        eventProperties.put(IdentityEventConstants.EventProperty.SCOPE_DESCRIPTION, scope.getDescription());
        eventProperties.put(IdentityEventConstants.EventProperty.SCOPE_DISPLAY_NAME, scope.getDisplayName());
        eventProperties.put(IdentityEventConstants.EventProperty.SCOPE_CLAIMS, scope.getClaim());

        Event event = createEvent(eventProperties, IdentityEventConstants.Event.PRE_UPDATE_SCOPE);
        doPublishEvent(event);
    }

    public void publishPostUpdateScope(int tenantId, ScopeDTO scope) {

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.TENANT_ID, tenantId);
        eventProperties.put(IdentityEventConstants.EventProperty.SCOPE_NAME, scope.getName());
        eventProperties.put(IdentityEventConstants.EventProperty.SCOPE_DESCRIPTION, scope.getDescription());
        eventProperties.put(IdentityEventConstants.EventProperty.SCOPE_DISPLAY_NAME, scope.getDisplayName());
        eventProperties.put(IdentityEventConstants.EventProperty.SCOPE_CLAIMS, scope.getClaim());

        Event event = createEvent(eventProperties, IdentityEventConstants.Event.POST_UPDATE_SCOPE);
        doPublishEvent(event);
    }

    public void publishPreDeleteScope(int tenantId, String scopeName) {

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.TENANT_ID, tenantId);
        eventProperties.put(IdentityEventConstants.EventProperty.SCOPE_NAME, scopeName);

        Event event = createEvent(eventProperties, IdentityEventConstants.Event.PRE_DELETE_SCOPE);
        doPublishEvent(event);
    }

    public void publishPostDeleteScope(int tenantId, String scopeName) {

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.TENANT_ID, tenantId);
        eventProperties.put(IdentityEventConstants.EventProperty.SCOPE_NAME, scopeName);

        Event event = createEvent(eventProperties, IdentityEventConstants.Event.POST_DELETE_SCOPE);
        doPublishEvent(event);
    }

    private Event createEvent(Map<String, Object> eventProperties, String eventName) {

        return new Event(eventName, eventProperties);
    }

    private void doPublishEvent(Event event) {

        try {
            if (log.isDebugEnabled()) {
                log.debug("Event: " + event.getEventName() + " is published for the claim management operation in " +
                        "the tenant with the tenantId: " + event.getEventProperties()
                        .get(IdentityEventConstants.EventProperty.TENANT_ID));
            }
            IdentityEventService eventService =
                    OAuthComponentServiceHolder.getInstance().getIdentityEventService();
            eventService.handleEvent(event);
        } catch (IdentityEventException e) {
            log.error("Error while publishing the event: " + event.getEventName() + ".", e);
        }
    }
}
