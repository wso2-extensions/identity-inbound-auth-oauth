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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementServiceImpl;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceComponentHolder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * Default implementation of CibaUserResolver.
 * 
 * Resolves user identity from CIBA login_hint using the underlying user store.
 */
public class DefaultCibaUserResolver implements CibaUserResolver {

    private static final Log log = LogFactory.getLog(DefaultCibaUserResolver.class);

    private static volatile DefaultCibaUserResolver instance;
    private static final String EMAIL_CLAIM = "http://wso2.org/claims/emailaddress";
    private static final String MOBILE_CLAIM = "http://wso2.org/claims/mobile";
    private static final String FIRST_NAME_CLAIM = "http://wso2.org/claims/givenname";
    private static final String USER_ID_CLAIM = "http://wso2.org/claims/userid";
    
    private static final String[] REQUIRED_CLAIMS = {EMAIL_CLAIM, MOBILE_CLAIM, FIRST_NAME_CLAIM, USER_ID_CLAIM};

    public static DefaultCibaUserResolver getInstance() {

        if (instance == null) {
            synchronized (DefaultCibaUserResolver.class) {
                if (instance == null) {
                    instance = new DefaultCibaUserResolver();
                }
            }
        }
        return instance;
    }

    @Override
    public ResolvedUser resolveUser(String loginHint, String tenantDomain) throws CibaCoreException {

        if (StringUtils.isBlank(loginHint)) {
            throw new CibaCoreException("login_hint cannot be blank");
        }

        if (StringUtils.isBlank(tenantDomain)) {
            tenantDomain = MultitenantUtils.getTenantDomain(loginHint);
            if (StringUtils.isBlank(tenantDomain)) {
                tenantDomain = "carbon.super";
            }
        }
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(loginHint);
        String userStoreDomain = UserCoreUtil.extractDomainFromName(tenantAwareUsername);
        if (StringUtils.isBlank(userStoreDomain)) {
            userStoreDomain = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
        }
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            UserStoreManager userStoreManager = getUserStoreManager(tenantDomain, tenantId, tenantAwareUsername);

            // Get user claims.
            Map<String, String> claimValues = userStoreManager.getUserClaimValues(
                    tenantAwareUsername, REQUIRED_CLAIMS, null);
            
            if (claimValues == null) {
                claimValues = new HashMap<>();
            }
            
            // Build resolved user.
            ResolvedUser resolvedUser = new ResolvedUser();
            resolvedUser.setUsername(tenantAwareUsername);
            resolvedUser.setUserStoreDomain(userStoreDomain);
            resolvedUser.setTenantDomain(tenantDomain);
            resolvedUser.setEmail(claimValues.get(EMAIL_CLAIM));
            resolvedUser.setMobile(claimValues.get(MOBILE_CLAIM));
            resolvedUser.setFirstName(claimValues.get(FIRST_NAME_CLAIM));
            resolvedUser.setUserId(claimValues.get(USER_ID_CLAIM));
            resolvedUser.setClaims(claimValues);
            
            if (log.isDebugEnabled()) {
                log.debug("Resolved user from login_hint: " + loginHint + 
                        ", username: " + tenantAwareUsername + 
                        ", email: " + (StringUtils.isNotBlank(resolvedUser.getEmail()) ? "present" : "not set") +
                        ", mobile: " + (StringUtils.isNotBlank(resolvedUser.getMobile()) ? "present" : "not set"));
            }
            
            return resolvedUser;
            
        } catch (UserStoreException e) {
            throw new CibaCoreException("Error resolving user from login_hint: " + loginHint, e);
        }
    }

    private static UserStoreManager getUserStoreManager(String tenantDomain, int tenantId, String tenantAwareUsername)
            throws CibaCoreException, UserStoreException {

        RealmService realmService = CibaServiceComponentHolder.getInstance().getRealmService();
        if (realmService == null) {
            throw new CibaCoreException("RealmService is not available");
        }

        UserRealm userRealm = realmService.getTenantUserRealm(tenantId);

        if (userRealm == null) {
            throw new CibaCoreException("User realm not found for tenant: " + tenantDomain);
        }

        UserStoreManager userStoreManager = userRealm.getUserStoreManager();

        // Check if user exists
        if (!userStoreManager.isExistingUser(tenantAwareUsername)) {
            throw new CibaCoreException("User not found for the provided login_hint");
        }
        return userStoreManager;
    }
}
