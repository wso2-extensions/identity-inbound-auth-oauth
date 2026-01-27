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

package org.wso2.carbon.identity.oauth.ciba.notifications;

import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.handlers.CibaUserResolver;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.user.core.common.User;

/**
 * SPI interface for CIBA notification channels.
 * 
 * This interface allows pluggable notification mechanisms for sending
 * authentication links to users. Implementations can support different
 * channels such as email, SMS, push notifications, etc.
 * 
 * Implementations are registered via OSGi and are selected based on
 * priority and capability to handle the notification context.
 */
public interface CibaNotificationChannel {

    /**
     * Get the priority of this notification channel.
     * Lower values indicate higher priority.
     * When multiple channels can handle a notification, the one
     * with the lowest priority value is used first.
     *
     * @return Priority value (lower = higher priority)
     */
    int getPriority();

    /**
     * Get the name of this notification channel.
     *
     * @return Channel name (e.g., "email", "sms")
     */
    String getName();

    /**
     * Check if this channel can handle notifications for the given user and context.
     * For example, an email channel would check if the user has a valid email address.
     *
     * @param resolvedUser          The user to send notification to
     * @param cibaAuthCodeDO CIBA auth code data object containing request details
     * @param tenantDomain  Tenant domain of the request
     * @return true if this channel can send the notification, false otherwise
     */
    boolean canHandle(CibaUserResolver.ResolvedUser resolvedUser, CibaAuthCodeDO cibaAuthCodeDO, String tenantDomain);

    /**
     * Send the authentication notification to the user.
     * The notification should contain a link to the /ciba-authorize endpoint
     * with the authCodeKey parameter.
     *
     * @param resolvedUser           The user to send notification to
     * @param cibaAuthCodeDO CIBA auth code data object containing request details
     * @param authUrl        The authentication URL to include in the notification
     * @param bindingMessage Optional binding message to display to user
     * @param tenantDomain   Tenant domain of the request
     * @throws CibaCoreException If notification sending fails
     */
    void sendNotification(CibaUserResolver.ResolvedUser resolvedUser, CibaAuthCodeDO cibaAuthCodeDO, String authUrl,
                          String bindingMessage, String tenantDomain) throws CibaCoreException;
}
