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
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;

/**
 * Implementation of CibaNotificationChannel for External channel.
 * This channel does not send any notification.
 */
public class ExternalNotificationChannel implements CibaNotificationChannel {

    private static final Log log = LogFactory.getLog(ExternalNotificationChannel.class);

    @Override
    public void sendNotification(CibaNotificationContext cibaNotificationContext) throws CibaCoreException {

        if (log.isDebugEnabled()) {
            log.debug("External notification channel selected. Skipping internal notification sending for user: " +
                    cibaNotificationContext.getResolvedUser().getUsername());
        }
        // No-op: Notification is handled externally.
    }

    @Override
    public boolean canHandle(CibaNotificationContext cibaNotificationContext) {

        // External channel should only be used when explicitly configured
        // as the app default or requested channel, not during fallback.
        return false;
    }

    @Override
    public String getName() {

        return CibaConstants.CibaNotificationChannel.EXTERNAL;
    }

    @Override
    public int getPriority() {

        return 5; // Default priority.
    }
}
