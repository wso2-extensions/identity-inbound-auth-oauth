/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.internal;

import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannelManager;
import org.wso2.carbon.identity.notification.push.device.handler.DeviceHandlerService;
import org.wso2.carbon.identity.oauth.ciba.resolvers.CibaUserResolver;
import org.wso2.carbon.identity.oauth.ciba.resolvers.impl.DefaultCibaUserResolverImpl;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Service holder for managing instances of Ciba related services.
 */
public class CibaServiceComponentHolder {

    private static CibaServiceComponentHolder instance = new CibaServiceComponentHolder();
    private static IdentityEventService identityEventService;
    private static RealmService realmService;
    private static CibaUserResolver cibaUserResolver;
    private static NotificationChannelManager notificationChannelManager;
    private static DeviceHandlerService deviceHandlerService;

    private CibaServiceComponentHolder() {

    }

    public static CibaServiceComponentHolder getInstance() {

        return instance;
    }

    public static IdentityEventService getIdentityEventService() {

        return identityEventService;
    }

    public static void setIdentityEventService(IdentityEventService identityEventService) {

        CibaServiceComponentHolder.identityEventService = identityEventService;
    }

    public static RealmService getRealmService() {

        return realmService;
    }

    public static void setRealmService(RealmService realmService) {

        CibaServiceComponentHolder.realmService = realmService;
    }

    public static NotificationChannelManager getNotificationChannelManager() {

        return notificationChannelManager;
    }

    public static void setNotificationChannelManager(
            NotificationChannelManager notificationChannelManager) {

        CibaServiceComponentHolder.notificationChannelManager = notificationChannelManager;
    }

    public DeviceHandlerService getDeviceHandlerService() {

        return deviceHandlerService;
    }

    public static void setDeviceHandlerService(DeviceHandlerService deviceHandlerService) {

        CibaServiceComponentHolder.deviceHandlerService = deviceHandlerService;
    }

    public static CibaUserResolver getCibaUserResolver() {

        if (cibaUserResolver == null) {
            synchronized (CibaUserResolver.class) {
                if (cibaUserResolver == null) {
                    try {
                        String defaultCibaUserResolverClassName = OAuthServerConfiguration.getInstance()
                                .getDefaultCibaUserResolverClassName();
                        Class clazz = Thread.currentThread().getContextClassLoader()
                                .loadClass(defaultCibaUserResolverClassName);
                        cibaUserResolver = (CibaUserResolver) clazz.newInstance();
                    } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
                        cibaUserResolver = new DefaultCibaUserResolverImpl();
                    }
                }
            }
        }
        return cibaUserResolver;
    }
}
