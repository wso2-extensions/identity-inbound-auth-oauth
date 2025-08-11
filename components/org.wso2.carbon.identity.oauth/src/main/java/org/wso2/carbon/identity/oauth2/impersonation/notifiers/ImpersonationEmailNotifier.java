/*
 *  Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.oauth2.impersonation.notifiers;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.oauth2.impersonation.exceptions.ImpersonationConfigMgtException;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationConfig;
import org.wso2.carbon.identity.oauth2.impersonation.services.ImpersonationConfigMgtService;
import org.wso2.carbon.identity.oauth2.impersonation.services.ImpersonationConfigMgtServiceImpl;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Locale;

/**
 * The ImpersonationEmailNotifier class is responsible for sending email notifications related to impersonation events.
 * It retrieves authenticated user details and triggers notification events when impersonation occurs,
 * ensuring that notifications are sent based on the configuration settings for each tenant domain.
 */
public class ImpersonationEmailNotifier {

    private static final Log LOG = LogFactory.getLog(ImpersonationEmailNotifier.class);
    private static final String UTC = "UTC";
    private static final String DATE_FORMAT = "MMMM dd, yyyy 'at' hh:mm a z";
    private static final String USER_NAME = "user-name";
    private static final String LOGIN_TIME = "login-time";
    private static final String IMPERSONATION_USER_NAME = "impersonator-user-name";
    private static final String TEMPLATE_TYPE_IMPERSONATION = "ImpersonationEmailNotification";
    private static final String TEMPLATE_TYPE = "TEMPLATE_TYPE";

    /**
     * Triggers a notification event when an impersonation occurs. This method checks if email notifications are
     * enabled for the tenant domain and, if so, sends an email notification with the impersonation details.
     *
     * @param subject        The ID of the user being impersonated.
     * @param impersonatorId The ID of the impersonator.
     * @param tenantDomain   The domain of the tenant where the impersonation occurred.
     * @param clientId       The client id.
     */
    public void triggerNotification(AuthenticatedUser subject, String impersonatorId, String tenantDomain,
                                    String clientId) {

        try {
            boolean sendEmail = isSendEmail(tenantDomain);

            if (sendEmail) {
                String eventName = IdentityEventConstants.Event.TRIGGER_NOTIFICATION;

                ZonedDateTime nowUtc = ZonedDateTime.now(ZoneId.of(UTC));

                DateTimeFormatter formatter = DateTimeFormatter.ofPattern(DATE_FORMAT, Locale.ENGLISH);

                String formattedDateTime = nowUtc.format(formatter);

                AuthenticatedUser impersonator;
                String userResidentTenantDomain;
                if (StringUtils.isNotBlank(subject.getAccessingOrganization()) &&
                        StringUtils.isNotBlank(subject.getUserStoreDomain())) {
                    impersonator = OAuth2Util.getAuthenticatedUserFromSubjectIdentifier(impersonatorId, tenantDomain,
                            subject.getAccessingOrganization(), subject.getUserResidentOrganization(), clientId);
                    userResidentTenantDomain = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                            .resolveTenantDomain(subject.getUserResidentOrganization());
                } else {
                    impersonator = OAuth2Util.getAuthenticatedUserFromSubjectIdentifier(impersonatorId, tenantDomain,
                            clientId);
                    userResidentTenantDomain = tenantDomain;
                }

                HashMap<String, Object> properties = new HashMap<>();
                properties.put(USER_NAME, subject.getUserName());
                properties.put(LOGIN_TIME, formattedDateTime);
                properties.put(IMPERSONATION_USER_NAME, impersonator.getUserName());

                properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, userResidentTenantDomain);
                properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, subject.getUserStoreDomain());
                properties.put(TEMPLATE_TYPE, TEMPLATE_TYPE_IMPERSONATION);

                Event identityMgtEvent = new Event(eventName, properties);
                OAuth2ServiceComponentHolder.getIdentityEventService().handleEvent(identityMgtEvent);
            }
        } catch (Exception e) {
            String errorMsg = "Error occurred while calling triggerNotification, detail : " + e.getMessage();
            /*
            We are not throwing any exception from here, because this event notification should not break the main
            flow.
             */
            LOG.warn(errorMsg);
            if (LOG.isDebugEnabled()) {
                LOG.debug(errorMsg, e);
            }
        }
    }

    /**
     * Determines if email notifications are enabled for the specified tenant domain. Retrieves the impersonation
     * configuration and checks if email notifications are enabled.
     *
     * @param tenantDomain The domain of the tenant to check for email notification settings.
     * @return True if email notifications are enabled, false otherwise.
     * @throws ImpersonationConfigMgtException If there is an error retrieving the impersonation configuration.
     */
    private static boolean isSendEmail(String tenantDomain) throws ImpersonationConfigMgtException {

        ImpersonationConfigMgtService impersonationConfigMgtService = new ImpersonationConfigMgtServiceImpl();
        ImpersonationConfig impersonationConfig = impersonationConfigMgtService
                .getImpersonationConfig(tenantDomain);
        return impersonationConfig.isEnableEmailNotification();
    }
}
