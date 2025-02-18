package org.wso2.carbon.identity.oauth.ciba.handlers;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
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
import org.wso2.carbon.identity.notification.push.device.handler.exception.PushDeviceHandlerException;
import org.wso2.carbon.identity.notification.push.device.handler.model.Device;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceComponentHolder;
import org.wso2.carbon.identity.oauth.ciba.model.CibaUserNotificationContext;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.ARBITRARY_SEND_TO;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.BINDING_MESSAGE;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.CHALLENGE;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.CIBA_APP_PLACEHOLDER_NAME;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.CIBA_AUTH_CODE_KEY;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.CIBA_BINDING_MESSAGE_PLACEHOLDER_NAME;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.CIBA_NOTIFICATION_SCENARIO;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.CIBA_USER_AUTH_ENDPOINT;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.CIBA_USER_LOGIN_LINK_PLACEHOLDER_NAME;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.DEFAULT_CIBA_USER_LOGIN_TEMPLATE_NAME;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.DEVICE_ID;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.DEVICE_TOKEN;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.LOGIN_HINT;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.NOTIFICATION_PROVIDER;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.NOTIFICATION_SCENARIO;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.PUSH_ID;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.PUSH_NOTIFICATION_CHANNEL;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.PUSH_NOTIFICATION_EVENT_NAME;
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
        AuthenticatedUser user = cibaUserNotificationContext.getAuthenticatedUser();
        try {
            // Build the user login request url which contains the auth code key, binding message and login hint.
            String userLoginRequestUrl = ServiceURLBuilder.create().addPath(CIBA_USER_AUTH_ENDPOINT)
                    .addParameter(CIBA_AUTH_CODE_KEY, cibaUserNotificationContext.getAuthCodeKey())
                    .addParameter(BINDING_MESSAGE, cibaUserNotificationContext.getBindingMessage())
                    .addParameter(LOGIN_HINT, user.toFullQualifiedUsername()).build().getAbsoluteInternalURL();
            // Resolve the communication channel of the user.
            String communicationChannel = notificationChannelManager
                    .resolveCommunicationChannel(user.getUserName(), user.getTenantDomain(),
                    user.getUserStoreDomain());
            if (NotificationChannels.EMAIL_CHANNEL.getChannelType().equalsIgnoreCase(communicationChannel)) {
                sendEmailNotification(cibaUserNotificationContext, userLoginRequestUrl);
            } else if (NotificationChannels.SMS_CHANNEL.getChannelType().equalsIgnoreCase(communicationChannel)) {
                sendSMSNotification(cibaUserNotificationContext, userLoginRequestUrl);
            } else if (PUSH_NOTIFICATION_CHANNEL.equalsIgnoreCase(communicationChannel)) {
                sendPushNotification(cibaUserNotificationContext, userLoginRequestUrl);
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
        AuthenticatedUser user = cibaUserNotificationContext.getAuthenticatedUser();
        Map<String, Object> properties = new HashMap<>();
        IdentityEventService eventService = CibaServiceComponentHolder.getIdentityEventService();
        String email = resolveEmailOfAuthenticatedUser(cibaUserNotificationContext.getAuthenticatedUser());
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUserName());
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
        AuthenticatedUser user = cibaUserNotificationContext.getAuthenticatedUser();
        Map<String, Object> properties = new HashMap<>();
        IdentityEventService eventService = CibaServiceComponentHolder.getIdentityEventService();
        String mobileNumber = resolveMobileNumberOfAuthenticatedUser(cibaUserNotificationContext
                .getAuthenticatedUser());
        properties.put(IdentityEventConstants.EventProperty.NOTIFICATION_CHANNEL,
                NotificationChannels.SMS_CHANNEL.getChannelType());
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUserName());
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

    /**
     * Send push notification to the user.
     *
     * @param cibaUserNotificationContext CibaUserNotificationContext.
     * @param userLoginRequestUrl         User login request url.
     * @throws CibaCoreException If an error occurred while sending the email notification.
     */
    private void sendPushNotification(CibaUserNotificationContext cibaUserNotificationContext,
                                      String userLoginRequestUrl)
            throws CibaCoreException {

        if (log.isDebugEnabled()) {
            log.debug("Sending push notification to the user.");
        }
        Map<String, Object> properties = new HashMap<>();
        IdentityEventService eventService = CibaServiceComponentHolder.getIdentityEventService();
        Device device = resolveDeviceOfAuthenticatedUser(cibaUserNotificationContext
                .getAuthenticatedUser());
        properties.put(IdentityEventConstants.EventProperty.NOTIFICATION_CHANNEL, PUSH_NOTIFICATION_CHANNEL);
        properties.put(NOTIFICATION_SCENARIO, CIBA_NOTIFICATION_SCENARIO);

        properties.put(PUSH_ID, UUID.randomUUID().toString());
        properties.put(DEVICE_TOKEN, device.getDeviceToken());
        properties.put(NOTIFICATION_PROVIDER, device.getProvider());
        properties.put(DEVICE_ID, device.getDeviceId());
        properties.put(CHALLENGE, userLoginRequestUrl);
        properties.put(CIBA_APP_PLACEHOLDER_NAME, cibaUserNotificationContext.getApplicationName());

        Event event = new Event(PUSH_NOTIFICATION_EVENT_NAME, properties);
        try {
            if (eventService != null) {
                eventService.handleEvent(event);
            }
        } catch (IdentityEventException e) {
            throw new CibaCoreException("Error in triggering the notification event", e);
        }
    }

    private String resolveEmailOfAuthenticatedUser(AuthenticatedUser user)
            throws CibaCoreException {

        return getUserClaimValueFromUserStore(NotificationChannels.EMAIL_CHANNEL.getClaimUri(), user);
    }

    private String resolveMobileNumberOfAuthenticatedUser(AuthenticatedUser user)
            throws CibaCoreException {

        return getUserClaimValueFromUserStore(NotificationChannels.SMS_CHANNEL.getClaimUri(), user);
    }

    private Device resolveDeviceOfAuthenticatedUser(AuthenticatedUser user)
            throws CibaCoreException {

        try {
            return CibaServiceComponentHolder.getInstance().getDeviceHandlerService()
                    .getDeviceByUserId(user.getUserId(), user.getTenantDomain());
        } catch (PushDeviceHandlerException e) {
            throw new CibaCoreException("Error in resolving the device of the user", e);
        } catch (UserIdNotFoundException e) {
            throw new CibaCoreException("Error in resolving the user id of the user", e);
        }
    }

    /**
     * Get user claim value.
     *
     * @param claimUri          Claim uri.
     * @param authenticatedUser AuthenticatedUser.
     * @return User claim value.
     * @throws CibaCoreException If an error occurred while getting the claim value.
     */
    private String getUserClaimValueFromUserStore(String claimUri, AuthenticatedUser authenticatedUser)
            throws CibaCoreException {

        UserStoreManager userStoreManager = getUserStoreManager(authenticatedUser);
        try {
            Map<String, String> claimValues =
                    userStoreManager.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(
                            authenticatedUser.toFullQualifiedUsername()), new String[]{claimUri}, null);
            return claimValues.get(claimUri);
        } catch (UserStoreException e) {
            throw new CibaCoreException("Error while getting the claim value: " + claimUri, e);
        }
    }

    /**
     * Get the user store manager.
     *
     * @param authenticatedUser Authenticated user.
     * @return User store manager.
     * @throws CibaCoreException If an error occurred while getting the user store manager.
     */
    private UserStoreManager getUserStoreManager(AuthenticatedUser authenticatedUser)
            throws CibaCoreException {

        UserRealm userRealm = getTenantUserRealm(authenticatedUser.getTenantDomain());
        String username = MultitenantUtils.getTenantAwareUsername(authenticatedUser.toFullQualifiedUsername());
        String userstoreDomain = authenticatedUser.getUserStoreDomain();
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
            userRealm = (CibaServiceComponentHolder.getInstance().getRealmService()).getTenantUserRealm(tenantId);
        } catch (UserStoreException e) {
            throw new CibaCoreException("Error in getting the user realm for the tenant: " + tenantDomain, e);
        }
        if (userRealm == null) {
            throw new CibaCoreException("User Realm is null for the tenant: " + tenantDomain);
        }
        return userRealm;
    }

}
