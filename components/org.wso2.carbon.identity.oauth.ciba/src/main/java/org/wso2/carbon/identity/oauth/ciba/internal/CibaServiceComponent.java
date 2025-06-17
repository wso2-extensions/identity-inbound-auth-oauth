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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannelManager;
import org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService;
import org.wso2.carbon.identity.oauth.ciba.api.CibaAuthService;
import org.wso2.carbon.identity.oauth.ciba.api.CibaAuthServiceImpl;
import org.wso2.carbon.identity.oauth.ciba.handlers.CibaResponseTypeRequestValidator;
import org.wso2.carbon.identity.oauth2.authz.validators.ResponseTypeRequestValidator;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Service component for CIBA.
 */
@Component(
        name = "identity.oauth.ciba.component",
        immediate = true
)
public class CibaServiceComponent {

    private static final Log log = LogFactory.getLog(CibaServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            context.getBundleContext().registerService(CibaAuthService.class.getName(),
                    new CibaAuthServiceImpl(), null);
            context.getBundleContext().registerService(ResponseTypeRequestValidator.class.getName(),
                    new CibaResponseTypeRequestValidator(), null);
            if (log.isDebugEnabled()) {
                log.debug("CIBA component bundle is activated.");
            }
        } catch (Throwable e) {
            log.error("Error occurred while activating CIBA Component.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("CIBA component bundle is deactivated.");
        }
    }

    @Reference(
            name = "org.wso2.carbon.identity.event.services.IdentityEventService",
            service = IdentityEventService.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityEventService"
    )
    protected void setIdentityEventService(IdentityEventService identityEventService) {

        if (log.isDebugEnabled()) {
            log.debug("IdentityEventService set in OAuth2ServiceComponent bundle");
        }
        CibaServiceComponentHolder.setIdentityEventService(identityEventService);
    }

    protected void unsetIdentityEventService(IdentityEventService identityEventService) {

        if (log.isDebugEnabled()) {
            log.debug("IdentityEventService unset in OAuth2ServiceComponent bundle");
        }
        CibaServiceComponentHolder.setIdentityEventService(null);
    }

    @Reference(
            name = "RealmService",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        CibaServiceComponentHolder.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        CibaServiceComponentHolder.setRealmService(null);
    }

    @Reference(
            name = "NotificationChannelManager",
            service = org.wso2.carbon.identity.governance.service.notification.NotificationChannelManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetNotificationChannelManager")
    protected void setNotificationChannelManager(NotificationChannelManager notificationChannelManager) {

        CibaServiceComponentHolder.setNotificationChannelManager(notificationChannelManager);
    }

    protected void unsetNotificationChannelManager(NotificationChannelManager notificationChannelManager) {

        CibaServiceComponentHolder.setNotificationChannelManager(null);
    }

    @Reference(
            name = "org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService",
            service = MultiAttributeLoginService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetMultiAttributeLoginService"
    )
    protected void setMultiAttributeLoginService(MultiAttributeLoginService multiAttributeLoginService) {

        CibaServiceComponentHolder.setMultiAttributeLoginService(multiAttributeLoginService);
    }

    protected void unsetMultiAttributeLoginService(MultiAttributeLoginService multiAttributeLoginService) {

        CibaServiceComponentHolder.setMultiAttributeLoginService(null);
    }
}
