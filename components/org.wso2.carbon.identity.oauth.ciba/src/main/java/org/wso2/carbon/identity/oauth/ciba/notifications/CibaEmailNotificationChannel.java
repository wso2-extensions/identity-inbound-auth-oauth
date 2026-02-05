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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.ciba.notifications;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannels;
import org.wso2.carbon.identity.oauth.ciba.common.CibaUtils;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.handlers.CibaUserResolver;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceComponentHolder;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.NOTIFICATION_CHANNEL;

/**
 * Email notification channel implementation for CIBA.
 * 
 * This channel sends authentication notifications via email using the
 * Identity Event framework's TRIGGER_NOTIFICATION event.
 */
public class CibaEmailNotificationChannel implements CibaNotificationChannel {

    private static final Log log = LogFactory.getLog(CibaEmailNotificationChannel.class);

    private static final String CHANNEL_NAME = "email";
    private static final int PRIORITY = 10;

    // Email template constants
    private static final String TEMPLATE_TYPE = "TEMPLATE_TYPE";
    private static final String CIBA_AUTH_EMAIL_TEMPLATE = "CIBAAuthenticationNotification";
    private static final String AUTH_URL = "ciba-auth-url";
    private static final String BINDING_MESSAGE_PARAM = "binding-message";
    private static final String USER_NAME = "user-name";
    private static final String EXPIRY_TIME = "expiry-time";
    private static final String SEND_TO = "send-to";

    @Override
    public int getPriority() {
        return PRIORITY;
    }

    @Override
    public String getName() {
        return CHANNEL_NAME;
    }

    @Override
    public boolean canHandle(CibaUserResolver.ResolvedUser resolvedUser, CibaAuthCodeDO cibaAuthCodeDO,
            String tenantDomain) {

        if (resolvedUser == null) {
            return false;
        }

        // Check if user has a valid email address
        try {
            String email = resolvedUser.getEmail();
            boolean hasEmail = StringUtils.isNotBlank(email);
            if (log.isDebugEnabled()) {
                log.debug("EmailCibaNotificationChannel.canHandle: User " + resolvedUser.getUsername() +
                        " has email: " + hasEmail);
            }
            return hasEmail;
        } catch (Exception e) {
            log.warn("Error checking email for user: " + resolvedUser.getUsername(), e);
            return false;
        }
    }

    @Override
    public void sendNotification(CibaUserResolver.ResolvedUser resolvedUser, CibaAuthCodeDO cibaAuthCodeDO,
            String authUrl,
            String bindingMessage, String tenantDomain) throws CibaCoreException {

        if (log.isDebugEnabled()) {
            log.debug("Sending CIBA authentication email to user: " + resolvedUser.getUsername() +
                    " with auth URL: " + authUrl);
        }
        String email = resolvedUser.getEmail();

        try {
            if (StringUtils.isBlank(email)) {
                throw new CibaCoreException("User does not have an email address configured.");
            }

            Map<String, Object> properties = new HashMap<>();
            properties.put(SEND_TO, email);
            properties.put(NOTIFICATION_CHANNEL, NotificationChannels.EMAIL_CHANNEL.getChannelType());
            properties.put(TEMPLATE_TYPE, CIBA_AUTH_EMAIL_TEMPLATE);
            properties.put(USER_NAME, resolvedUser.getUsername());
            properties.put(AUTH_URL, authUrl);
            properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, tenantDomain);
            String expiryTimeInString = CibaUtils.getExpiryTimeAsString(cibaAuthCodeDO.getExpiresIn());
            properties.put(EXPIRY_TIME, expiryTimeInString);
            if (StringUtils.isNotBlank(bindingMessage)) {
                properties.put(BINDING_MESSAGE_PARAM, bindingMessage);
            }

            Event event = new Event("TRIGGER_NOTIFICATION", properties);

            CibaServiceComponentHolder.getInstance().getIdentityEventService().handleEvent(event);
        } catch (Exception e) {
            throw new CibaCoreException("Error preparing CIBA email notification for user: " +
                    resolvedUser.getUsername(), e);
        }
    }
}
