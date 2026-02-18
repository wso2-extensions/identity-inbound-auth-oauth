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
     * @param cibaNotificationContext Context containing notification details
     * @return true if this channel can send the notification, false otherwise
     * @throws CibaCoreException If error occurs while checking handling capability
     */
    boolean canHandle(CibaNotificationContext cibaNotificationContext) throws CibaCoreException;

    /**
     * Send the authentication notification to the user.
     * The notification should contain a link to the /ciba-authorize endpoint
     * with the authCodeKey parameter.
     *
     * @param cibaNotificationContext Context containing notification details
     * @throws CibaCoreException If notification sending fails
     */
    void sendNotification(CibaNotificationContext cibaNotificationContext) throws CibaCoreException;
}
