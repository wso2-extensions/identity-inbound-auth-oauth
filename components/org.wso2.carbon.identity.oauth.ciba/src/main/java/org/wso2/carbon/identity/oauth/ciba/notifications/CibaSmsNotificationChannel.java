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
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannels;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.common.CibaUtils;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.handlers.CibaUserResolver;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceComponentHolder;
import org.wso2.carbon.user.core.common.User;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.NOTIFICATION_CHANNEL;

/**
 * SMS notification channel implementation for CIBA.
 * 
 * This channel sends authentication notifications via SMS using the
 * Identity Event framework's TRIGGER_SMS_NOTIFICATION event.
 */
public class CibaSmsNotificationChannel implements CibaNotificationChannel {

    private static final Log log = LogFactory.getLog(CibaSmsNotificationChannel.class);

    private static final int PRIORITY = 20;
    
    // SMS template constants
    private static final String TEMPLATE_TYPE = "TEMPLATE_TYPE";
    private static final String CIBA_AUTH_SMS_TEMPLATE = "CIBASMSAuthenticationNotification2";
    private static final String AUTH_URL = "ciba-auth-url";
    private static final String BINDING_MESSAGE_PARAM = "binding-message";
    private static final String MOBILE_NUMBER = "http://wso2.org/claims/mobile";
    private static final String SEND_TO = "send-to";
    private static final String EXPIRY_TIME = "expiry-time";
    private static final String TRIGGER_SMS_NOTIFICATION = "TRIGGER_SMS_NOTIFICATION_LOCAL";

    @Override
    public int getPriority() {
        return PRIORITY;
    }

    @Override
    public String getName() {

        return CibaConstants.CibaNotificationChannel.SMS;
    }

    @Override
    public boolean canHandle(CibaNotificationContext cibaNotificationContext) {

        CibaUserResolver.ResolvedUser resolvedUser = cibaNotificationContext.getResolvedUser();
        if (resolvedUser == null) {
            return false;
        }
        
        // Check if user has a valid mobile number.
        try {
            String mobile = resolvedUser.getMobile();
            boolean hasMobile = StringUtils.isNotBlank(mobile);
            if (log.isDebugEnabled()) {
                log.debug("SmsCibaNotificationChannel.canHandle: User " + resolvedUser.getUsername() +
                        " has mobile: " + hasMobile);
            }
            return hasMobile;
        } catch (Exception e) {
            log.warn("Error checking mobile for user: " + resolvedUser.getUsername(), e);
            return false;
        }
    }

    @Override
    public void sendNotification(CibaNotificationContext cibaNotificationContext) throws CibaCoreException {

        CibaUserResolver.ResolvedUser resolvedUser = cibaNotificationContext.getResolvedUser();
        String authUrl = cibaNotificationContext.getAuthUrl();
        String bindingMessage = cibaNotificationContext.getBindingMessage();
        if (log.isDebugEnabled()) {
            log.debug("Sending CIBA authentication SMS to user: " + resolvedUser.getUsername() +
                    " with auth URL: " + authUrl);
        }

        try {
            String mobile = resolvedUser.getMobile();
            if (StringUtils.isBlank(mobile)) {
                throw new CibaCoreException("User does not have a mobile number configured.");
            }

            // Build event properties for the SMS notification.
            Map<String, Object> properties = new HashMap<>();
            properties.put(IdentityEventConstants.EventProperty.USER_NAME, resolvedUser.getUsername());
            properties.put(NOTIFICATION_CHANNEL, NotificationChannels.SMS_CHANNEL.getChannelType());
            properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN,
                    cibaNotificationContext.getTenantDomain());
            properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, resolvedUser.getUserStoreDomain());
            properties.put(TEMPLATE_TYPE, CIBA_AUTH_SMS_TEMPLATE);
            String expiryTimeInString = CibaUtils.getExpiryTimeAsString(cibaNotificationContext.getExpiryTime());
            properties.put(EXPIRY_TIME, expiryTimeInString);
            properties.put(SEND_TO, mobile);
            properties.put(AUTH_URL, authUrl);
            
            if (StringUtils.isNotBlank(bindingMessage)) {
                properties.put(BINDING_MESSAGE_PARAM, bindingMessage);
            }

            // Trigger the SMS notification event
            Event identityEvent = new Event(TRIGGER_SMS_NOTIFICATION, properties);
            CibaServiceComponentHolder.getInstance().getIdentityEventService().handleEvent(identityEvent);

            if (log.isDebugEnabled()) {
                log.debug("Successfully triggered CIBA SMS notification for user: " + resolvedUser.getUserId());
            }
        } catch (IdentityEventException e) {
            throw new CibaCoreException("Error sending CIBA SMS notification to user: " + 
                    resolvedUser.getUserId(), e);
        }
    }

    /**
     * Get the mobile number of the user from their claims.
     *
     * @param user The user object
     * @return Mobile number or null if not found
     */
    private String getUserMobile(User user) {

        if (user.getAttributes() != null) {
            Map<String, String> attributes = user.getAttributes();
            return attributes.get(MOBILE_NUMBER);
        }
        return null;
    }
}
