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
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaClientException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.internal.CibaServiceComponentHolder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreClientException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * Default implementation of CibaUserResolver.
 * <p>
 * Resolves user identity from CIBA login_hint using the underlying user store.
 */
public class DefaultCibaUserResolver implements CibaUserResolver {

    private static final Log log = LogFactory.getLog(DefaultCibaUserResolver.class);

    private static volatile DefaultCibaUserResolver instance;
    private static final String EMAIL_CLAIM = "http://wso2.org/claims/emailaddress";
    private static final String MOBILE_CLAIM = "http://wso2.org/claims/mobile";
    private static final String USER_ID_CLAIM = "http://wso2.org/claims/userid";

    private static final String[] REQUIRED_CLAIMS = { EMAIL_CLAIM, MOBILE_CLAIM, USER_ID_CLAIM };

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
    public ResolvedUser resolveUser(String loginHint, String tenantDomain)
            throws CibaClientException, CibaCoreException {

        if (StringUtils.isBlank(loginHint)) {
            throw new CibaCoreException("login_hint cannot be blank");
        }

        if (StringUtils.isBlank(tenantDomain)) {
            tenantDomain = MultitenantUtils.getTenantDomain(loginHint);
            if (StringUtils.isBlank(tenantDomain)) {
                tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            }
        }
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(loginHint);
        String userStoreDomain = UserCoreUtil.extractDomainFromName(tenantAwareUsername);
        if (StringUtils.isBlank(userStoreDomain)) {
            userStoreDomain = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
        }

        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            UserStoreManager userStoreManager = getUserStoreManager(tenantDomain, tenantId);

            boolean isUserFound = false;
            String resolvedUserId = null;
            String resolvedUsername = null;
            Map<String, String> claimValues = null;

            // 1. Try to resolve as a Username.
            if (userStoreManager.isExistingUser(tenantAwareUsername)) {
                isUserFound = true;
                resolvedUsername = tenantAwareUsername;
                claimValues = userStoreManager.getUserClaimValues(resolvedUsername, REQUIRED_CLAIMS, null);
            }

            // 2. If not found, try to resolve as a User ID.
            if (!isUserFound && userStoreManager instanceof AbstractUserStoreManager) {
                AbstractUserStoreManager abstractUserStoreManager = (AbstractUserStoreManager) userStoreManager;
                // Identifying the login hint as a possible user ID.
                try {
                    if (abstractUserStoreManager.isExistingUserWithID(tenantAwareUsername)) {
                        isUserFound = true;
                        resolvedUserId = tenantAwareUsername;
                        resolvedUsername = abstractUserStoreManager.getUserNameFromUserID(resolvedUserId);
                        claimValues = abstractUserStoreManager.getUserClaimValuesWithID(resolvedUserId, REQUIRED_CLAIMS,
                                null);
                    }
                } catch (Exception e) {
                    // Ignore exception and fallback to not found.
                    log.warn("Error while resolving user with user ID: " + LoggerUtils.getMaskedContent(
                            tenantAwareUsername), e);
                }
            }

            if (!isUserFound) {
                throw new CibaClientException("Invalid login_hint provided.");
            }

            if (claimValues == null) {
                claimValues = new HashMap<>();
            }

            // Build resolved user.
            ResolvedUser resolvedUser = new ResolvedUser();
            resolvedUser.setUsername(resolvedUsername);
            resolvedUser.setUserStoreDomain(userStoreDomain);
            resolvedUser.setTenantDomain(tenantDomain);
            resolvedUser.setEmail(claimValues.get(EMAIL_CLAIM));
            resolvedUser.setMobile(claimValues.get(MOBILE_CLAIM));

            // If resolvedUserId is null (resolved by username), get it from claims.
            if (resolvedUserId == null) {
                resolvedUserId = claimValues.get(USER_ID_CLAIM);
            }
            resolvedUser.setUserId(resolvedUserId);
            resolvedUser.setClaims(claimValues);
            return resolvedUser;

        } catch (UserStoreClientException e) {
            throw new CibaClientException("Client error resolving user from login_hint: " + loginHint, e);
        } catch (UserStoreException e) {
            throw new CibaCoreException("Error resolving user from login_hint: " + loginHint, e);
        }
    }

    private static UserStoreManager getUserStoreManager(String tenantDomain, int tenantId)
            throws CibaCoreException, UserStoreException {

        RealmService realmService = CibaServiceComponentHolder.getInstance().getRealmService();
        if (realmService == null) {
            throw new CibaCoreException("RealmService is not available");
        }
        UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
        if (userRealm == null) {
            throw new CibaCoreException("User realm not found for tenant: " + tenantDomain);
        }
        return userRealm.getUserStoreManager();
    }
}
