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


package org.wso2.carbon.identity.oauth.ciba.handlers;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.exceptions.notiification.NotificationChannelManagerException;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannelManager;
import org.wso2.carbon.identity.governance.service.notification.NotificationChannels;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceComponentHolder;
import org.wso2.carbon.identity.oauth.ciba.model.CibaUserNotificationContext;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.ARBITRARY_SEND_TO;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.CIBA_APP_PLACEHOLDER_NAME;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.CIBA_AUTH_CODE_KEY;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.CIBA_BINDING_MESSAGE_PLACEHOLDER_NAME;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.CIBA_USER_AUTH_ENDPOINT;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.CIBA_USER_LOGIN_LINK_PLACEHOLDER_NAME;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.DEFAULT_CIBA_USER_LOGIN_TEMPLATE_NAME;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.SMS_EVENT_TRIGGER_NAME;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.TEMPLATE_TYPE;
import static org.wso2.carbon.user.core.UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;

/**
 * This class is responsible for sending the login request notification to the user.
 */
public class CibaUserNotificationHandler {

    private static final Log log = LogFactory.getLog(CibaUserNotificationHandler.class);

    /**
     * Send the login request notification to the user.
     *
     * @param cibaUserNotificationContext CibaUserNotificationContext.
     * @throws CibaCoreException If an error occurred while sending the notification.
     */
    public void sendNotification(CibaUserNotificationContext cibaUserNotificationContext) throws CibaCoreException {

        NotificationChannelManager notificationChannelManager =
                CibaServiceComponentHolder.getNotificationChannelManager();
        User user = cibaUserNotificationContext.getUser();
        try {
            // Build the user login request url which contains the auth code key, binding message and login hint.
            String userLoginRequestUrl = ServiceURLBuilder.create().addPath(CIBA_USER_AUTH_ENDPOINT)
                    .addParameter(CIBA_AUTH_CODE_KEY, cibaUserNotificationContext.getAuthCodeKey())
                    .build().getAbsoluteInternalURL();
            // Resolve the communication channel of the user. If the preferred channel of user is configured,
            // we will resolve the communication channel and send the notification. This need to be improved in the
            // future to support push notification.
            String communicationChannel = notificationChannelManager.resolveCommunicationChannel(user.getUsername(),
                    user.getTenantDomain(), user.getUserStoreDomain());
            if (NotificationChannels.EMAIL_CHANNEL.getChannelType().equalsIgnoreCase(communicationChannel)) {
                sendEmailNotification(cibaUserNotificationContext, userLoginRequestUrl);
            } else if (NotificationChannels.SMS_CHANNEL.getChannelType().equalsIgnoreCase(communicationChannel)) {
                sendSMSNotification(cibaUserNotificationContext, userLoginRequestUrl);
            }
        } catch (NotificationChannelManagerException e) {
            throw new CibaCoreException("Error in resolving the communication channel for the user", e);
        } catch (URLBuilderException e) {
            throw new CibaCoreException("Error in building the user login request url", e);
        }
    }

    /**
     * Send email notification to the user.
     *
     * @param cibaUserNotificationContext CibaUserNotificationContext.
     * @param userLoginRequestUrl         User login request url.
     * @throws CibaCoreException If an error occurred while sending the email notification.
     */
    private void sendEmailNotification(CibaUserNotificationContext cibaUserNotificationContext,
                                       String userLoginRequestUrl) throws CibaCoreException {

        if (log.isDebugEnabled()) {
            log.debug("Sending email notification to the user.");
        }
        User user = cibaUserNotificationContext.getUser();
        Map<String, Object> properties = new HashMap<>();
        IdentityEventService eventService = CibaServiceComponentHolder.getIdentityEventService();
        String email = resolveEmailOfAuthenticatedUser(cibaUserNotificationContext.getUser());
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUsername());
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
        properties.put(TEMPLATE_TYPE, DEFAULT_CIBA_USER_LOGIN_TEMPLATE_NAME);
        properties.put(CIBA_USER_LOGIN_LINK_PLACEHOLDER_NAME, userLoginRequestUrl);
        properties.put(CIBA_BINDING_MESSAGE_PLACEHOLDER_NAME, cibaUserNotificationContext
                .getBindingMessage());
        properties.put(CIBA_APP_PLACEHOLDER_NAME, cibaUserNotificationContext.getApplicationName());
        properties.put(ARBITRARY_SEND_TO, email);

        Event event = new Event(IdentityEventConstants.Event.TRIGGER_NOTIFICATION, properties);
        try {
            if (eventService != null) {
                eventService.handleEvent(event);
            }
        } catch (IdentityEventException e) {
            throw new CibaCoreException("Error in triggering the notification event", e);
        }
    }

    /**
     * Send SMS notification to the user.
     *
     * @param cibaUserNotificationContext CibaUserNotificationContext.
     * @param userLoginRequestUrl         User login request url.
     * @throws CibaCoreException If an error occurred while sending the email notification.
     */
    private void sendSMSNotification(CibaUserNotificationContext cibaUserNotificationContext,
                                     String userLoginRequestUrl)
            throws CibaCoreException {

        if (log.isDebugEnabled()) {
            log.debug("Sending sms notification to the user.");
        }
        User user = cibaUserNotificationContext.getUser();
        Map<String, Object> properties = new HashMap<>();
        IdentityEventService eventService = CibaServiceComponentHolder.getIdentityEventService();
        String mobileNumber = resolveMobileNumberOfAuthenticatedUser(cibaUserNotificationContext
                .getUser());
        properties.put(IdentityEventConstants.EventProperty.NOTIFICATION_CHANNEL,
                NotificationChannels.SMS_CHANNEL.getChannelType());
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUsername());
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
        properties.put(ARBITRARY_SEND_TO, mobileNumber);
        properties.put(TEMPLATE_TYPE, DEFAULT_CIBA_USER_LOGIN_TEMPLATE_NAME);
        properties.put(CIBA_USER_LOGIN_LINK_PLACEHOLDER_NAME, userLoginRequestUrl);
        properties.put(CIBA_BINDING_MESSAGE_PLACEHOLDER_NAME, cibaUserNotificationContext
                .getBindingMessage());
        properties.put(CIBA_APP_PLACEHOLDER_NAME, cibaUserNotificationContext.getApplicationName());

        Event event = new Event(SMS_EVENT_TRIGGER_NAME, properties);
        try {
            if (eventService != null) {
                eventService.handleEvent(event);
            }
        } catch (IdentityEventException e) {
            throw new CibaCoreException("Error in triggering the notification event", e);
        }
    }

    private String resolveEmailOfAuthenticatedUser(User user)
            throws CibaCoreException {

        return getUserClaimValueFromUserStore(NotificationChannels.EMAIL_CHANNEL.getClaimUri(), user);
    }

    private String resolveMobileNumberOfAuthenticatedUser(User user)
            throws CibaCoreException {

        return getUserClaimValueFromUserStore(NotificationChannels.SMS_CHANNEL.getClaimUri(), user);
    }

    /**
     * Get user claim value.
     *
     * @param claimUri Claim uri.
     * @param user     User.
     * @return User claim value.
     * @throws CibaCoreException If an error occurred while getting the claim value.
     */
    private String getUserClaimValueFromUserStore(String claimUri, User user)
            throws CibaCoreException {

        UserStoreManager userStoreManager = getUserStoreManager(user);
        try {
            Map<String, String> claimValues =
                    userStoreManager.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(
                            user.getFullQualifiedUsername()), new String[]{claimUri}, null);
            return claimValues.get(claimUri);
        } catch (UserStoreException e) {
            throw new CibaCoreException("Error while getting the claim value: " + claimUri, e);
        }
    }

    /**
     * Get the user store manager.
     *
     * @param user User.
     * @return User store manager.
     * @throws CibaCoreException If an error occurred while getting the user store manager.
     */
    private UserStoreManager getUserStoreManager(User user)
            throws CibaCoreException {

        UserRealm userRealm = getTenantUserRealm(user.getTenantDomain());
        String username = MultitenantUtils.getTenantAwareUsername(user.getFullQualifiedUsername());
        String userstoreDomain = user.getUserStoreDomain();
        try {
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (userStoreManager == null) {
                throw new CibaCoreException("User Store Manager is null for the user: " + username);
            }
            if (StringUtils.isBlank(userstoreDomain) || PRIMARY_DEFAULT_DOMAIN_NAME.equals(userstoreDomain)) {
                return userStoreManager;
            }
            return ((AbstractUserStoreManager) userStoreManager).getSecondaryUserStoreManager(userstoreDomain);
        } catch (UserStoreException e) {
            throw new CibaCoreException("Error in getting the user store manager for the user: " + username, e);
        }
    }

    private UserRealm getTenantUserRealm(String tenantDomain)
            throws CibaCoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        UserRealm userRealm;
        try {
            userRealm = (CibaServiceComponentHolder.getRealmService()).getTenantUserRealm(tenantId);
        } catch (UserStoreException e) {
            throw new CibaCoreException("Error in getting the user realm for the tenant: " + tenantDomain, e);
        }
        if (userRealm == null) {
            throw new CibaCoreException("User Realm is null for the tenant: " + tenantDomain);
        }
        return userRealm;
    }

}
