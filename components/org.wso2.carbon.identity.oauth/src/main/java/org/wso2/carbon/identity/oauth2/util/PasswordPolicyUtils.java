/*
 * Copyright (c) 2010-2021, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.oauth2.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConfigBuilder;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.ModuleConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.PasswordPolicyConstants;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Map;
import java.util.Optional;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

/**
 * Helper functions for Password Grant Password Expiry enforcement
 */
public class PasswordPolicyUtils {
    private static final Log log = LogFactory.getLog(PasswordPolicyUtils.class);

    private PasswordPolicyUtils() {
    }

    /**
     * Get the identity property specified in identity-event.properties.
     *
     * @param propertyName The name of the property which should be fetched.
     * @return The required property.
     */
    public static Optional<String> getIdentityEventProperty(String propertyName) {

        // Retrieving properties set in identity event properties
        Optional<String> propertyValue = Optional.empty();
        try {
            ModuleConfiguration moduleConfiguration = IdentityEventConfigBuilder.getInstance()
                    .getModuleConfigurations(PasswordPolicyConstants.PASSWORD_CHANGE_EVENT_HANDLER_NAME);

            if (moduleConfiguration != null && moduleConfiguration.getModuleProperties() != null) {
                propertyValue = Optional.of(moduleConfiguration.getModuleProperties().getProperty(propertyName));
            }
        } catch (IdentityEventException e) {
            log.warn("An error occurred while retrieving module properties");
            if (log.isDebugEnabled()) {
                log.debug("An error occurred while retrieving module properties because " + e.getMessage(), e);
            }
        }
        return propertyValue;
    }

    /**
     * Retrieve the password expiry property from resident IdP.
     *
     * @param tenantDomain tenant domain which user belongs to.
     * @param propertyName name of the property to be retrieved.
     * @return the value of the requested property.
     * @throws IdentityOAuth2Exception if retrieving property from resident idp fails.
     */
    public static Optional<String> getResidentIdpProperty(String tenantDomain, String propertyName)
            throws IdentityOAuth2Exception {

        IdentityProvider residentIdP;
        try {
            residentIdP = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);

            if (residentIdP == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Resident IdP is not found for tenant: " + tenantDomain);
                }
                return Optional.empty();
            }
        } catch (IdentityProviderManagementException e) {
            throw new IdentityOAuth2Exception("Error occurred while retrieving the resident IdP for tenant: " +
                    tenantDomain, e);
        }

        IdentityProviderProperty property = IdentityApplicationManagementUtil
                .getProperty(residentIdP.getIdpProperties(), propertyName);

        String propertyValue = null;
        if (property != null) {
            propertyValue = property.getValue();
        }
        return Optional.ofNullable(propertyValue);
    }

    /**
     * Checks if the password had expired.
     *
     * @param tenantDomain        The tenant domain of the user trying to authenticate.
     * @param tenantAwareUsername The tenant aware username of the user trying to authenticate.
     * @return True if the password had expired.
     * @throws IdentityOAuth2Exception if the authentication failed for the user trying to login.
     */
    public static boolean isUserPasswordExpired(String tenantDomain, String tenantAwareUsername)
            throws IdentityOAuth2Exception {

        org.wso2.carbon.user.api.UserStoreManager userStoreManager;
        UserRealm userRealm;
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            userStoreManager = userRealm.getUserStoreManager();
        } catch (UserStoreException e) {
            throw new IdentityOAuth2Exception("Error occurred while loading user manager from user realm", e);
        }

        String passwordLastChangedTime;
        String lastCredentialUpdateClaimURI = PasswordPolicyConstants.LAST_CREDENTIAL_UPDATE_TIMESTAMP_CLAIM;
        String createdClaimURI = PasswordPolicyConstants.CREATED_CLAIM;
        try {
            // trying to first get a value for the 'lastPasswordUpdateTime' claim and if that fails the fallback is
            // the 'created' claim
            passwordLastChangedTime = getClaimValue(userStoreManager, lastCredentialUpdateClaimURI, tenantAwareUsername)
                    .orElse(convertCreatedDateToEpochString(
                            getClaimValue(userStoreManager, createdClaimURI, tenantAwareUsername).get()));
        } catch (UserStoreException | ParseException e) {
            throw new IdentityOAuth2Exception("Error occurred while loading user claim", e);
        }

        long passwordChangedTime;
        passwordChangedTime = Long.parseLong(passwordLastChangedTime);

        int daysDifference = 0;
        long currentTimeMillis = System.currentTimeMillis();
        if (passwordChangedTime > 0) {
            Calendar currentTime = Calendar.getInstance();
            currentTime.add(Calendar.DATE, (int) currentTime.getTimeInMillis());
            daysDifference = (int) TimeUnit.MILLISECONDS.toDays(currentTimeMillis - passwordChangedTime);
        }

        int passwordExpiryInDays = PasswordPolicyConstants.PASSWORD_EXPIRY_IN_DAYS_DEFAULT_VALUE;

        // Getting the configured number of days before password expiry in days
        String passwordExpiryInDaysConfiguredValue = getResidentIdpProperty(tenantDomain,
                PasswordPolicyConstants.PASSWORD_EXPIRY_IN_DAYS_FROM_CONFIG)
                .orElseGet(() -> getIdentityEventProperty(
                        PasswordPolicyConstants.PASSWORD_EXPIRY_IN_DAYS_FROM_CONFIG).get());

        if (StringUtils.isNotBlank(passwordExpiryInDaysConfiguredValue)) {
            passwordExpiryInDays = Integer.parseInt(passwordExpiryInDaysConfiguredValue);
        }

        return daysDifference > passwordExpiryInDays;
    }

    private static Optional<String> getClaimValue(org.wso2.carbon.user.api.UserStoreManager userStoreManager,
                                                  String claimURI,
                                                  String tenantAwareUsername) throws UserStoreException {

        String[] claimURIs = new String[]{claimURI};
        Map<String, String> claimValueMap =
                userStoreManager.getUserClaimValues(tenantAwareUsername, claimURIs, null);
        if (claimValueMap != null && !claimValueMap.isEmpty()) {
            return Optional.of(claimValueMap.get(claimURI));
        }
        return Optional.empty();
    }

    private static String convertCreatedDateToEpochString(String createdDate) throws ParseException {

        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(PasswordPolicyConstants.CREATED_CLAIM_DATE_FORMAT);
        simpleDateFormat.setTimeZone(TimeZone.getTimeZone(PasswordPolicyConstants.CREATED_CLAIM_TIMEZONE));

        return String.valueOf(simpleDateFormat.parse(createdDate).getTime());
    }
}
