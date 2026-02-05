/*
 * Copyright (c) 2019-2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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
import org.wso2.carbon.identity.oauth.ciba.api.CibaAuthService;
import org.wso2.carbon.identity.oauth.ciba.api.CibaAuthServiceImpl;
import org.wso2.carbon.identity.oauth.ciba.handlers.CibaResponseTypeRequestValidator;
import org.wso2.carbon.identity.oauth.ciba.handlers.CibaUserResolver;
import org.wso2.carbon.identity.oauth.ciba.handlers.DefaultCibaUserResolver;
import org.wso2.carbon.identity.oauth.ciba.notifications.CibaEmailNotificationChannel;
import org.wso2.carbon.identity.oauth.ciba.notifications.CibaNotificationChannel;
import org.wso2.carbon.identity.oauth.ciba.notifications.CibaSmsNotificationChannel;
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
            // Register CIBA Auth Service
            context.getBundleContext().registerService(CibaAuthService.class.getName(),
                    new CibaAuthServiceImpl(), null);
            
            // Register default notification channels
            CibaEmailNotificationChannel emailChannel = new CibaEmailNotificationChannel();
            CibaSmsNotificationChannel smsChannel = new CibaSmsNotificationChannel();
            
            context.getBundleContext().registerService(CibaNotificationChannel.class.getName(),
                    emailChannel, null);
            context.getBundleContext().registerService(CibaNotificationChannel.class.getName(),
                    smsChannel, null);

            context.getBundleContext().registerService(ResponseTypeRequestValidator.class.getName(),
                    new CibaResponseTypeRequestValidator(), null);
            context.getBundleContext().registerService(CibaUserResolver.class.getName(),
                    DefaultCibaUserResolver.getInstance(), null);
            
            if (log.isDebugEnabled()) {
                log.debug("CIBA component bundle is activated. Registered default notification channels.");
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
            name = "identity.event.service",
            service = IdentityEventService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityEventService"
    )
    protected void setIdentityEventService(IdentityEventService identityEventService) {

        CibaServiceComponentHolder.getInstance().setIdentityEventService(identityEventService);
        if (log.isDebugEnabled()) {
            log.debug("IdentityEventService set in CIBA component.");
        }
    }

    protected void unsetIdentityEventService(IdentityEventService identityEventService) {

        CibaServiceComponentHolder.getInstance().setIdentityEventService(null);
        if (log.isDebugEnabled()) {
            log.debug("IdentityEventService unset in CIBA component.");
        }
    }

    @Reference(
            name = "ciba.notification.channel",
            service = CibaNotificationChannel.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetNotificationChannel"
    )
    protected void setNotificationChannel(CibaNotificationChannel channel) {

        CibaServiceComponentHolder.getInstance().addNotificationChannel(channel);
        if (log.isDebugEnabled()) {
            log.debug("CIBA notification channel registered: " + channel.getName() + 
                    " with priority: " + channel.getPriority());
        }
    }

    protected void unsetNotificationChannel(CibaNotificationChannel channel) {

        CibaServiceComponentHolder.getInstance().removeNotificationChannel(channel);
        if (log.isDebugEnabled()) {
            log.debug("CIBA notification channel unregistered: " + channel.getName());
        }
    }

    @Reference(
            name = "user.realm.service",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        CibaServiceComponentHolder.getInstance().setRealmService(realmService);
        if (log.isDebugEnabled()) {
            log.debug("RealmService set in CIBA component.");
        }
    }

    protected void unsetRealmService(RealmService realmService) {

        CibaServiceComponentHolder.getInstance().setRealmService(null);
        if (log.isDebugEnabled()) {
            log.debug("RealmService unset in CIBA component.");
        }
    }

    @Reference(
            name = "ciba.user.resolver",
            service = CibaUserResolver.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetCibaUserResolver"
    )
    protected void setCibaUserResolver(CibaUserResolver cibaUserResolver) {

        CibaServiceComponentHolder.getInstance().setCibaUserResolver(cibaUserResolver);
        if (log.isDebugEnabled()) {
            log.debug("CibaUserResolver set in CIBA component: " + cibaUserResolver.getClass().getName());
        }
    }

    protected void unsetCibaUserResolver(CibaUserResolver cibaUserResolver) {

        CibaServiceComponentHolder.getInstance().setCibaUserResolver(null);
        if (log.isDebugEnabled()) {
            log.debug("CibaUserResolver unset in CIBA component.");
        }
    }
}
