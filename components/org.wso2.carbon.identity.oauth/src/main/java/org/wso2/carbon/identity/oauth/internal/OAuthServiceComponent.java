/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor;
import org.wso2.carbon.identity.oauth.listener.IdentityOathEventListener;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="identity.oauth.component" immediate="true"
 * @scr.reference name="registry.service"
 * interface="org.wso2.carbon.registry.core.service.RegistryService"
 * cardinality="1..1" policy="dynamic" bind="setRegistryService"
 * unbind="unsetRegistryService"
 * @scr.reference name="org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor"
 * interface="org.wso2.carbon.identity.oauth.event.OAuthEventInterceptor"
 * cardinality="0..n" policy="dynamic"
 * bind="setOAuthEventInterceptorProxy"
 * unbind="unsetOAuthEventInterceptor"
 * @scr.reference name="identityCoreInitializedEventService"
 * interface="org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent" cardinality="1..1"
 * policy="dynamic" bind="setIdentityCoreInitializedEventService" unbind="unsetIdentityCoreInitializedEventService"
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService" cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class OAuthServiceComponent {

    private static Log log = LogFactory.getLog(OAuthServiceComponent.class);
    private static IdentityOathEventListener listener = null;
    private ServiceRegistration serviceRegistration = null;

    protected void activate(ComponentContext context) {
        // initialize the OAuth Server configuration
        OAuthServerConfiguration oauthServerConfig = OAuthServerConfiguration.getInstance();

        if (oauthServerConfig.isCacheEnabled()) {
            log.debug("OAuth Caching is enabled. Initializing the cache.");
            // initialize the cache
            OAuthCache cache = OAuthCache.getInstance();
            if (cache != null) {
                log.debug("OAuth Cache initialization was successful.");
            } else {
                log.debug("OAuth Cache initialization was unsuccessful.");
            }
        }

        listener = new IdentityOathEventListener();
        serviceRegistration = context.getBundleContext().registerService(UserOperationEventListener.class.getName(),
                listener, null);
        log.debug("Identity Oath Event Listener is enabled");

        if (log.isDebugEnabled()) {
            log.debug("Identity OAuth bundle is activated");
        }
    }

    protected void deactivate(ComponentContext context) {

        if (serviceRegistration != null) {
            serviceRegistration.unregister();
        }
        if (log.isDebugEnabled()) {
            log.debug("Identity OAuth bundle is deactivated");
        }
    }

    protected void setRegistryService(RegistryService registryService) {

        if (log.isDebugEnabled()) {
            log.debug("RegistryService set in Identity OAuth bundle");
        }
        OAuthComponentServiceHolder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {

        if (log.isDebugEnabled()) {
            log.debug("RegistryService unset in Identity OAuth bundle");
        }
        OAuthComponentServiceHolder.getInstance().setRegistryService(null);
    }

    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service");
        }
        OAuthComponentServiceHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting the Realm Service");
        }
        OAuthComponentServiceHolder.getInstance().setRealmService(null);
    }

    protected void setOAuthEventInterceptorProxy(OAuthEventInterceptor oAuthEventInterceptor) {

        if (oAuthEventInterceptor == null) {
            log.warn("Null Oauth Event Interceptor received, hence not registering");
            return;
        }

        if (!OAuthConstants.OAUTH_INTERCEPTOR_PROXY.equalsIgnoreCase(oAuthEventInterceptor.getName())) {
            log.debug("Non proxy Oauth event interceptor received, hence not registering");
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("Setting oauth event interceptor proxy :" + oAuthEventInterceptor.getClass().getName());
        }
        OAuthComponentServiceHolder.getInstance().addOauthEventInterceptorProxy(oAuthEventInterceptor);
    }

    protected void unsetOAuthEventInterceptor(OAuthEventInterceptor oAuthEventInterceptor) {

        if (oAuthEventInterceptor == null) {
            log.warn("Null oauth event interceptor received, hence not registering");
            return;
        }

        if (!OAuthConstants.OAUTH_INTERCEPTOR_PROXY.equalsIgnoreCase(oAuthEventInterceptor.getName())) {
            log.debug("Non proxy Oauth event interceptor received, hence not un-setting");
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("Un-setting oauth event interceptor proxy :" + oAuthEventInterceptor.getClass().getName());
        }
        OAuthComponentServiceHolder.getInstance().addOauthEventInterceptorProxy(null);
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }
}