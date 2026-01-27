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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.ciba.handlers.CibaUserResolver;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.user.core.common.User;

/**
 * DEBUG/TESTING ONLY: Console notification channel that prints auth URL to console.
 * 
 * This channel has the lowest priority (highest number) and will be used as a fallback
 * when no other channels can handle the notification. It simply prints the authentication
 * URL to the console/logs for debugging purposes.
 * 
 * TODO: Remove this before production deployment!
 */
public class ConsoleCibaNotificationChannel implements CibaNotificationChannel {

    private static final Log log = LogFactory.getLog(ConsoleCibaNotificationChannel.class);

    private static final String CHANNEL_NAME = "console";
    private static final int PRIORITY = 1000; // Lowest priority - fallback

    @Override
    public int getPriority() {
        return PRIORITY;
    }

    @Override
    public String getName() {
        return CHANNEL_NAME;
    }

    @Override
    public boolean canHandle(CibaUserResolver.ResolvedUser resolvedUser, CibaAuthCodeDO cibaAuthCodeDO, String tenantDomain) {
        // Always can handle - this is the fallback
        return true;
    }

    @Override
    public void sendNotification(CibaUserResolver.ResolvedUser resolvedUser, CibaAuthCodeDO cibaAuthCodeDO, String authUrl,
                                 String bindingMessage, String tenantDomain) {

        // Print to console with high visibility
        System.out.println("\n" + "=".repeat(80));
        System.out.println("  [CIBA DEBUG] Authentication URL for user: " + 
                (resolvedUser != null ? resolvedUser.getUsername() : "unknown"));
        System.out.println("=".repeat(80));
        System.out.println("  AUTH URL: " + authUrl);
        if (bindingMessage != null) {
            System.out.println("  BINDING MESSAGE: " + bindingMessage);
        }
        System.out.println("  AUTH_REQ_ID: " + cibaAuthCodeDO.getAuthReqId());
        System.out.println("=".repeat(80) + "\n");

        // Also log it
        log.info("[CIBA DEBUG] Authentication URL: " + authUrl);
    }
}
