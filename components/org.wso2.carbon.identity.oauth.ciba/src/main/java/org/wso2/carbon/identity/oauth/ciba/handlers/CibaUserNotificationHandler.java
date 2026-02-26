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

package org.wso2.carbon.identity.oauth.ciba.handlers;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaClientException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceComponentHolder;
import org.wso2.carbon.identity.oauth.ciba.notifications.CibaNotificationChannel;
import org.wso2.carbon.identity.oauth.ciba.notifications.CibaNotificationContext;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Handles sending notifications to users for CIBA authentication.
 * <p>
 * This handler builds the authentication URL and uses the registered
 * notification channels (via SPI) to send the notification to the user.
 */
public class CibaUserNotificationHandler {

    private static final Log log = LogFactory.getLog(CibaUserNotificationHandler.class);

    /**
     * Send notification to user with the authentication link.
     *
     * @param notificationContext Context containing details for notification.
     * @throws CibaCoreException If notification sending fails.
     */
    public String sendNotification(CibaNotificationContext notificationContext) throws CibaCoreException,
            CibaClientException {

        CibaUserResolver.ResolvedUser resolvedUser = notificationContext.getResolvedUser();
        if (resolvedUser == null) {
            throw new CibaCoreException("Resolved user cannot be null");
        }

        if (notificationContext.getAppAllowedChannels().isEmpty()) {
            throw new CibaClientException(
                    "No notification channels configured for the application.");
        }

        // Get registered notification channels.
        List<CibaNotificationChannel> channels = new ArrayList<>(CibaServiceComponentHolder.getInstance()
                .getNotificationChannels());
        if (channels.isEmpty()) {
            log.warn("No notification channels registered. User will not receive CIBA notification.");
            return null;
        }

        String requestedChannel = notificationContext.getRequestedChannel();

        // 1. If a specific channel is requested, validate it against the supported list and send.
        if (StringUtils.isNotEmpty(requestedChannel)) {
            if (isChannelDisallowed(notificationContext.getAppAllowedChannels(), requestedChannel)) {
                throw new CibaClientException("Requested notification channel is not allowed for this application.");
            }
            return sendToTargetChannel(channels, notificationContext, requestedChannel);
        }

        // 2. Fallback: Send notification via supported channels in priority order.
        return sendToAllAllowedChannels(channels, notificationContext, resolvedUser);
    }

    private String sendToTargetChannel(List<CibaNotificationChannel> channels,
                                       CibaNotificationContext notificationContext,
                                       String targetChannelName) throws CibaCoreException {

        for (CibaNotificationChannel channel : channels) {
            if (!channel.getName().equalsIgnoreCase(targetChannelName)) {
                continue;
            }
            if (!channel.canHandle(notificationContext)) {
                throw new CibaCoreException(
                        "Target channel '" + targetChannelName + "' cannot handle this notification.");
            }
            if (log.isDebugEnabled()) {
                log.debug("Sending CIBA notification via target channel: " + channel.getName());
            }
            channel.sendNotification(notificationContext);
            return channel.getName();
        }
        throw new CibaCoreException("Target notification channel not found: " + targetChannelName);
    }

    private String sendToAllAllowedChannels(List<CibaNotificationChannel> channels,
                                            CibaNotificationContext notificationContext,
                                            CibaUserResolver.ResolvedUser resolvedUser)
            throws CibaCoreException {

        channels.sort(Comparator.comparingInt(CibaNotificationChannel::getPriority));

        String lastSuccessfulChannel = null;
        for (CibaNotificationChannel channel : channels) {
            if (isChannelDisallowed(notificationContext.getAppAllowedChannels(), channel.getName())) {
                if (log.isDebugEnabled()) {
                    log.debug("Skipping channel '" + channel.getName()
                            + "' as it is not in the allowed list.");
                }
                continue;
            }
            try {
                if (channel.canHandle(notificationContext)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Sending CIBA notification via channel: " + channel.getName());
                    }
                    channel.sendNotification(notificationContext);
                    lastSuccessfulChannel = channel.getName();
                }
            } catch (CibaCoreException e) {
                log.warn("Failed to send notification via channel: " + channel.getName()
                        + ", error: " + e.getMessage());
            }
        }

        if (lastSuccessfulChannel == null) {
            log.warn("Could not send CIBA notification to user: " + resolvedUser.getUsername()
                    + ". No suitable channel found or all channels failed.");
        }
        return lastSuccessfulChannel;
    }

    private boolean isChannelDisallowed(List<String> allowedChannels, String channelName) {

        return !allowedChannels.contains(channelName.toLowerCase());
    }
}
