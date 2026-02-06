/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth.ciba.handlers.CibaUserResolver;
import org.wso2.carbon.identity.oauth.ciba.handlers.DefaultCibaUserResolver;
import org.wso2.carbon.identity.oauth.ciba.notifications.CibaNotificationChannel;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Holder class for CIBA service component dependencies.
 * 
 * This singleton holds references to OSGi services and components
 * needed by the CIBA module, including notification channels.
 */
public class CibaServiceComponentHolder {

    private static final CibaServiceComponentHolder instance = new CibaServiceComponentHolder();
    
    private IdentityEventService identityEventService;
    private RealmService realmService;
    private CibaUserResolver cibaUserResolver;
    private final List<CibaNotificationChannel> notificationChannels = new ArrayList<>();

    private CibaServiceComponentHolder() {
    }

    public static CibaServiceComponentHolder getInstance() {
        return instance;
    }

    /**
     * Get the Identity Event Service.
     *
     * @return IdentityEventService instance
     */
    public IdentityEventService getIdentityEventService() {

        return identityEventService;
    }

    /**
     * Set the Identity Event Service.
     *
     * @param identityEventService IdentityEventService instance
     */
    public void setIdentityEventService(IdentityEventService identityEventService) {

        this.identityEventService = identityEventService;
    }

    /**
     * Get the Realm Service.
     *
     * @return RealmService instance
     */
    public RealmService getRealmService() {
        return realmService;
    }

    /**
     * Set the Realm Service.
     *
     * @param realmService RealmService instance
     */
    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    /**
     * Add a notification channel.
     *
     * @param channel CibaNotificationChannel implementation
     */
    public void addNotificationChannel(CibaNotificationChannel channel) {
        notificationChannels.add(channel);
        // Sort by priority after adding
        notificationChannels.sort(Comparator.comparingInt(CibaNotificationChannel::getPriority));
    }

    /**
     * Remove a notification channel.
     *
     * @param channel CibaNotificationChannel implementation to remove
     */
    public void removeNotificationChannel(CibaNotificationChannel channel) {
        notificationChannels.remove(channel);
    }

    /**
     * Get all registered notification channels sorted by priority.
     *
     * @return List of notification channels sorted by priority (lowest first)
     */
    public List<CibaNotificationChannel> getNotificationChannels() {
        return Collections.unmodifiableList(notificationChannels);
    }

    /**
     * Get the CIBA User Resolver.
     * Returns the configured resolver or falls back to DefaultCibaUserResolver.
     *
     * @return CibaUserResolver instance
     */
    public CibaUserResolver getCibaUserResolver() {

        if (cibaUserResolver != null) {
            return cibaUserResolver;
        }
        return DefaultCibaUserResolver.getInstance();
    }

    /**
     * Set the CIBA User Resolver.
     *
     * @param cibaUserResolver CibaUserResolver instance
     */
    public void setCibaUserResolver(CibaUserResolver cibaUserResolver) {

        this.cibaUserResolver = cibaUserResolver;
    }
}
