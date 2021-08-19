/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth.listener;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserSessionException;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.mgt.SessionManagementException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.role.mgt.core.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.mgt.core.UserBasicInfo;
import org.wso2.carbon.identity.role.mgt.core.dao.RoleDAO;
import org.wso2.carbon.identity.role.mgt.core.dao.RoleMgtDAOFactory;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.util.ArrayList;
import java.util.List;

/**
 * This is an event handler listening for some of the core user management operations.
 */
public class IdentityOauthEventHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(IdentityOauthEventHandler.class);
    private final RoleDAO roleDAO = RoleMgtDAOFactory.getInstance().getRoleDAO();

    public String getName() {

        return "identityOauthEventHandler";
    }

    public String getFriendlyName() {

        return "Identity Oauth Event Handler";
    }

    @Override
    public void init(InitConfig configuration) throws IdentityRuntimeException {

        super.init(configuration);
    }

    @Override
    public int getPriority(MessageContext messageContext) {

        int priority = super.getPriority(messageContext);
        if (priority == -1) {
            priority = 51;
        }
        return priority;
    }


    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        if (IdentityEventConstants.Event.POST_SET_USER_CLAIMS.equals(event.getEventName()) ||
                IdentityEventConstants.Event.POST_SET_USER_CLAIM.equals(event.getEventName())) {
            String username = (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.USER_NAME);
            UserStoreManager userStoreManager =
                    (UserStoreManager) event.getEventProperties()
                            .get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
            try {
                revokeTokensOfLockedUser(username, userStoreManager);
                revokeTokensOfDisabledUser(username, userStoreManager);
                OAuthUtil.removeUserClaimsFromCache(username, userStoreManager);
            } catch (UserStoreException e) {
                String errorMsg = "Error occurred while revoking  access token for User : " + username;
                log.error(errorMsg, e);
                throw new IdentityEventException(errorMsg);
            }

        } else if (IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE.equals(event.getEventName())) {

            Object userIdList = event.getEventProperties()
                    .get(IdentityEventConstants.EventProperty.DELETE_USER_ID_LIST);
            List<String> deletedUserIDList;

            if (userIdList instanceof List<?>) {
                deletedUserIDList = (List<String>) userIdList;
                terminateSession(deletedUserIDList);
            }

        } else if (IdentityEventConstants.Event.PRE_DELETE_ROLE.equals(event.getEventName()) ||
                IdentityEventConstants.Event.POST_SET_PERMISSIONS_FOR_ROLE.equals(event.getEventName())) {

            String roleId = (String) event.getEventProperties()
                    .get(IdentityEventConstants.EventProperty.ROLE_ID);
            String tenantDomain = (String) event.getEventProperties()
                    .get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);
            try {
                List<UserBasicInfo> userList = roleDAO.getRole(roleId, tenantDomain).getUsers();

                List<String> userIdList = new ArrayList<>();
                if (userList != null) {
                    for (UserBasicInfo userBasicInfo : userList) {
                        userIdList.add(userBasicInfo.getId());
                    }
                    terminateSession(userIdList);
                }
            } catch (IdentityRoleManagementException e) {
                String errorMsg = "Invaild role id :" + roleId + "in tenant domain " + tenantDomain;
                throw new IdentityEventException(errorMsg);
            }
        }
    }

    private void revokeTokensOfLockedUser(String userName, UserStoreManager userStoreManager)
            throws UserStoreException {

        String errorCode =
                (String) IdentityUtil.threadLocalProperties.get().get(IdentityCoreConstants.USER_ACCOUNT_STATE);

        if (UserCoreConstants.ErrorCode.USER_IS_LOCKED.equalsIgnoreCase(errorCode)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("User %s is locked. Hence revoking user's access tokens.", userName));
            }
            OAuthUtil.revokeTokens(userName, userStoreManager);
        }
    }

    private void revokeTokensOfDisabledUser(String userName, UserStoreManager userStoreManager)
            throws UserStoreException {

        String errorCode =
                (String) IdentityUtil.threadLocalProperties.get().get(IdentityCoreConstants.USER_ACCOUNT_STATE);
        if (IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE.equalsIgnoreCase(errorCode)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("User %s is disabled. Hence revoking user's access tokens.", userName));
            }
            OAuthUtil.revokeTokens(userName, userStoreManager);
        }
    }

    /**
     * To revoke access tokens and terminate sessions of given list of user IDs.
     *
     * @param userIDList            List of user IDs
     * @throws IdentityEventException
     */
    private void terminateSession(List<String> userIDList) throws IdentityEventException {

        try {
            UserStoreManager userStoreManager = (UserStoreManager) CarbonContext.getThreadLocalCarbonContext()
                    .getUserRealm().getUserStoreManager();

            String userName;
            if (CollectionUtils.isNotEmpty(userIDList)) {
                for (String userId : userIDList) {
                    try {
                        userName = FrameworkUtils.resolveUserNameFromUserId(userStoreManager, userId);
                        OAuthUtil.revokeTokens(userName, userStoreManager);
                        OAuthUtil.removeUserClaimsFromCache(userName, userStoreManager);
                        OAuth2ServiceComponentHolder.getUserSessionManagementService()
                                .terminateSessionsByUserId(userId);
                    } catch (UserSessionException e) {
                        String errorMsg = "Error occurred while revoking access token for user Id: " + userId;
                        log.error(errorMsg, e);
                        throw new IdentityEventException(errorMsg, e);
                    } catch (SessionManagementException e) {
                        String errorMsg = "Failed to terminate active sessions of user Id: " + userId;
                        log.error(errorMsg, e);
                        throw new IdentityEventException(errorMsg, e);
                    }
                }
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMsg = "Error occurred while retrieving user manager";
            log.error(errorMsg, e);
            throw new IdentityEventException(errorMsg, e);
        }
    }
}
