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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceComponentHolder;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.ciba.notifications.CibaNotificationChannel;
import org.wso2.carbon.user.core.common.User;

import java.util.List;

/**
 * Handles sending notifications to users for CIBA authentication.
 * 
 * This handler builds the authentication URL and uses the registered
 * notification channels (via SPI) to send the notification to the user.
 */
public class CibaUserNotificationHandler {

    private static final Log log = LogFactory.getLog(CibaUserNotificationHandler.class);

    /**
     * Send notification to user with the authentication link.
     *
     * @param resolvedUser    The resolved user from login_hint
     * @param cibaAuthCodeDO  The CIBA auth code data object
     * @param bindingMessage  Optional binding message
     * @throws CibaCoreException If notification sending fails
     */
    public void sendNotification(CibaUserResolver.ResolvedUser resolvedUser, 
                                  CibaAuthCodeDO cibaAuthCodeDO,
                                  String bindingMessage) throws CibaCoreException {

        if (resolvedUser == null) {
            throw new CibaCoreException("Resolved user cannot be null");
        }
        
        if (cibaAuthCodeDO == null) {
            throw new CibaCoreException("CibaAuthCodeDO cannot be null");
        }

        // Build the authentication URL
        String authUrl = buildAuthenticationUrl(cibaAuthCodeDO.getCibaAuthCodeKey());
        
        if (log.isDebugEnabled()) {
            log.debug("Built CIBA authentication URL for user: " + resolvedUser.getUsername() + 
                    ", URL: " + authUrl);
        }

        String tenantDomain = resolvedUser.getTenantDomain();

        // Get registered notification channels
        List<CibaNotificationChannel> channels = CibaServiceComponentHolder.getInstance()
                .getNotificationChannels();

        if (channels.isEmpty()) {
            log.warn("No notification channels registered. User will not receive CIBA notification.");
            return;
        }

        boolean notificationSent = false;

        // Try each channel in priority order
        for (CibaNotificationChannel channel : channels) {
            try {
                if (channel.canHandle(resolvedUser, cibaAuthCodeDO, tenantDomain)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Sending CIBA notification via channel: " + channel.getName());
                    }
                    
                    channel.sendNotification(resolvedUser, cibaAuthCodeDO, authUrl, bindingMessage, tenantDomain);
                    notificationSent = true;
                    
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully sent CIBA notification via: " + channel.getName());
                    }
                    
                    // Successfully sent via one channel, can break
                    // If you want to send via ALL applicable channels, remove this break
                    break;
                }
            } catch (CibaCoreException e) {
                log.warn("Failed to send notification via channel: " + channel.getName() + 
                        ", error: " + e.getMessage());
                // Continue to try other channels
            }
        }

        if (!notificationSent) {
            log.warn("Could not send CIBA notification to user: " + resolvedUser.getUsername() + 
                    ". No suitable channel found or all channels failed.");
        }
    }

    /**
     * Build the authentication URL that the user will click.
     *
     * @param authCodeKey The auth code key for the CIBA session
     * @return The full authentication URL
     * @throws CibaCoreException If URL building fails
     */
    private String buildAuthenticationUrl(String authCodeKey) throws CibaCoreException {
        
        try {
            return ServiceURLBuilder.create()
                    .addPath(CibaConstants.CIBA_USER_AUTH_ENDPOINT)
                    .addParameter(CibaConstants.CIBA_AUTH_CODE_KEY, authCodeKey)
                    .build()
                    .getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new CibaCoreException("Error building CIBA authentication URL", e);
        }
    }
}
