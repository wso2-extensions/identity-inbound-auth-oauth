/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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
 */

package org.wso2.carbon.identity.oauth.internal.util;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.OIDCConstants;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.wso2.carbon.identity.openidconnect.OIDCConstants.Event.EXISTING_TOKEN_USED;

/**
 * Utility class for publishing OAuth related events.
 * This class provides methods to publish token revoke events with various parameters.
 * It uses the Identity Event Service to handle the event publication.
 */
public class AccessTokenEventUtil {

    private static final Log LOG = LogFactory.getLog(AccessTokenEventUtil.class);
    private static final String APP_DAO = "OAuthAppDO";

    /**
     * Publishes a token revoke event for a particular user.
     *
     * @param consumerKeys Set of consumer keys associated with the revoked tokens.
     * @param user         Authenticated user whose tokens are revoked.
     */
    public static void publishTokenRevokeEvent(Set<String> consumerKeys, AuthenticatedUser user) {

        Map<String, Object> properties = baseProperties(user);
        properties.put(IdentityEventConstants.EventProperty.CONSUMER_KEYS, consumerKeys);
        publish(properties);
    }

    /**
     * Publishes a token revoke event with the specified access token details.
     *
     * @param token AccessTokenDO object containing details of the revoked token.
     */
    public static void publishTokenRevokeEvent(AccessTokenDO token) {

        if (token == null) {
            return;
        }

        Map<String, Object> properties = baseProperties(token.getAuthzUser());
        properties.put(IdentityEventConstants.EventProperty.CONSUMER_KEYS,
                Collections.singletonList(token.getConsumerKey()));
        publish(properties);
    }

    /**
     * Publishes a token revoke event with the specified application ID,
     * consumer key, removed scopes, and tenant domain.
     *
     * @param applicationResourceId Application ID associated with the revoked tokens.
     * @param consumerKey           Consumer key of the application.
     * @param tenantDomain          Tenant domain of the application.
     */
    public static void publishTokenRevokeEvent(String applicationResourceId, String consumerKey,
                                               String tenantDomain) {

        Map<String, Object> properties = baseTenantProperties(tenantDomain);
        properties.put(IdentityEventConstants.EventProperty.CONSUMER_KEYS, Collections.singletonList(consumerKey));
        properties.put(IdentityEventConstants.EventProperty.APPLICATION_ID, applicationResourceId);
        publish(properties);
    }

    /**
     * Publishes a token revoke event with the specified application resource ID, application name, consumer key,
     * and tenant domain.
     *
     * @param applicationResourceId Resource ID of the application.
     * @param appName               Name of the application.
     * @param consumerKey           Consumer key of the application.
     * @param tenantDomain          Tenant domain of the application.
     */
    public static void publishTokenRevokeEvent(String applicationResourceId, String appName, String consumerKey,
                                               String tenantDomain) {

        Map<String, Object> properties = baseTenantProperties(tenantDomain);
        properties.put(IdentityEventConstants.EventProperty.CONSUMER_KEYS, Collections.singletonList(consumerKey));
        properties.put(IdentityEventConstants.EventProperty.APPLICATION_ID, applicationResourceId);
        properties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME, appName);
        publish(properties);
    }

    /**
     * Publishes a token revoke event for a specific tenant domain and consumer key.
     *
     * @param tenantDomain    Tenant domain of the application.
     * @param consumerKey     Consumer key of the application.
     * @param serviceProvider ServiceProvider object containing application details.
     */
    public static void publishTokenRevokeEvent(String tenantDomain, String consumerKey,
                                               ServiceProvider serviceProvider) {

        Map<String, Object> properties = baseTenantProperties(tenantDomain);
        if (serviceProvider != null) {
            properties.put(IdentityEventConstants.EventProperty.CONSUMER_KEYS, Collections.singletonList(consumerKey));
            properties.put(IdentityEventConstants.EventProperty.APPLICATION_ID,
                    serviceProvider.getApplicationResourceId());
            properties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME, serviceProvider.getApplicationName());
        }
        publish(properties);
    }

    /**
     * Publishes a token revoke event for a specific tenant ID and user store name.
     *
     * @param tenantId      Tenant ID of the user store.
     * @param userStoreName Name of the user store.
     * @param tokens        Set of AccessTokenDO objects representing the revoked tokens.
     */
    public static void publishTokenRevokeEvent(int tenantId, String userStoreName, Set<AccessTokenDO> tokens) {

        Map<String, Object> properties = new HashMap<>();
        setFirstTokenUserProperties(properties, tokens);
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, userStoreName);
        properties.put(IdentityEventConstants.EventProperty.TENANT_ID, tenantId);
        publish(properties);
    }

    /**
     * Publishes a token revoke event for a specific tenant ID and set of AccessTokenDO objects.
     *
     * @param tenantId Tenant ID of the user store.
     * @param tokens   Set of AccessTokenDO objects representing the revoked tokens.
     */
    public static void publishTokenRevokeEvent(int tenantId, Set<AccessTokenDO> tokens) {

        Map<String, Object> properties = new HashMap<>();
        setFirstTokenUserProperties(properties, tokens);
        properties.put(IdentityEventConstants.EventProperty.TENANT_ID, tenantId);
        publish(properties);
    }

    /**
     * Publishes a token revoke event for a specific consumer key and token binding reference.
     *
     * @param consumerKey Consumer key of the application.
     * @param user        Authenticated user whose tokens are revoked.
     */
    public static void publishTokenRevokeEvent(String consumerKey, AuthenticatedUser user) {

        Map<String, Object> properties = baseProperties(user);
        properties.put(IdentityEventConstants.EventProperty.CONSUMER_KEYS, Collections.singletonList(consumerKey));
        publish(properties);
    }

    private static Map<String, Object> baseProperties(AuthenticatedUser user) {

        Map<String, Object> properties = new HashMap<>();
        if (user != null) {
            try {
                properties.put(IdentityEventConstants.EventProperty.USER_ID, user.getUserId());
            } catch (UserIdNotFoundException e) {
                LOG.debug("Error retrieving user Id for tenant: " + user.getTenantDomain(), e);
            }
            properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUserName());
            properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
            properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
        }
        properties.put(IdentityEventConstants.EventProperty.TENANT_ID,
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId());
        return properties;
    }

    private static Map<String, Object> baseTenantProperties(String tenantDomain) {

        Map<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, tenantDomain);
        properties.put(IdentityEventConstants.EventProperty.TENANT_ID,
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId());
        return properties;
    }

    private static void setFirstTokenUserProperties(Map<String, Object> properties, Set<AccessTokenDO> tokens) {

        if (tokens != null && !tokens.isEmpty()) {
            AccessTokenDO first = tokens.iterator().next();
            AuthenticatedUser user = first.getAuthzUser();
            if (user != null) {
                properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
                properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
            }
        }
    }

    private static void publish(Map<String, Object> properties) {

        Event event = new Event(IdentityEventConstants.Event.TOKEN_REVOKED, properties);
        try {
            OpenIDConnectServiceComponentHolder.getIdentityEventService().handleEvent(event);
        } catch (IdentityEventException e) {
            LOG.warn("Error occurred publishing event " + IdentityEventConstants.Event.TOKEN_REVOKED, e);
        }
    }

    /**
     * Publishes an event when a token is issued.
     *
     * @param tokReqMsgCtx            The token request message context containing information about the token request.
     * @param oAuth2AccessTokenReqDTO The OAuth2 access token request DTO containing details about the access token
     *                                request.
     * @throws UserIdNotFoundException If the user ID cannot be found in the context.
     */
    public static void publishTokenIssueEvent(OAuthTokenReqMessageContext tokReqMsgCtx,
                                              OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO)
            throws UserIdNotFoundException, OrganizationManagementException, IdentityOAuth2Exception {

        HashMap<String, Object> properties = new HashMap<>();

        OauthTokenIssuer tokenIssuer = null;
        try {
            tokenIssuer = OAuth2Util.getOAuthTokenIssuerForOAuthApp(oAuth2AccessTokenReqDTO.getClientId());
        } catch (IdentityOAuth2Exception e) {
            LOG.error("Error while retrieving the OAuth token issuer for client ID: " +
                    oAuth2AccessTokenReqDTO.getClientId(), e);
        } catch (InvalidOAuthClientException e) {
            LOG.error("Invalid OAuth client with client ID: " + oAuth2AccessTokenReqDTO.getClientId(), e);
        }
        if (tokenIssuer != null) {
            properties.put(IdentityEventConstants.EventProperty.TOKEN_TYPE, tokenIssuer.getAccessTokenType());
        }

        if (tokReqMsgCtx != null) {

            String issuerTenant = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();
            String issuerOrganizationId = OAuthComponentServiceHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(issuerTenant);
            String accessingOrganizationId = StringUtils.EMPTY;
            if (tokReqMsgCtx.getAuthorizedUser() != null
                    && tokReqMsgCtx.getAuthorizedUser().getAccessingOrganization() != null) {
                accessingOrganizationId = tokReqMsgCtx.getAuthorizedUser().getAccessingOrganization();
            }

            if (tokReqMsgCtx.getAuthorizedUser() != null) {
                properties.put(IdentityEventConstants.EventProperty.USER_ID,
                        tokReqMsgCtx.getAuthorizedUser().getUserId());
                properties.put(IdentityEventConstants.EventProperty.USER_NAME,
                        tokReqMsgCtx.getAuthorizedUser().getUserName());
                properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN,
                        tokReqMsgCtx.getAuthorizedUser().getUserStoreDomain());
                properties.put(IdentityEventConstants.EventProperty.IS_ORGANIZATION_USER,
                        tokReqMsgCtx.getAuthorizedUser().isOrganizationUser());
                properties.put(IdentityEventConstants.EventProperty.USER_RESIDENT_ORGANIZATION_ID,
                        tokReqMsgCtx.getAuthorizedUser().getUserResidentOrganization());
            }

            properties.put(OIDCConstants.Event.USER_TYPE,
                    tokReqMsgCtx.getProperty(OAuthConstants.UserType.USER_TYPE));
            properties.put(OIDCConstants.Event.CLIENT_ID,
                    tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId());
            properties.put(OIDCConstants.Event.ISSUED_TIME,
                    String.valueOf(tokReqMsgCtx.getAccessTokenIssuedTime()));
            properties.put(EXISTING_TOKEN_USED,
                    String.valueOf(existingTokenUsed(tokReqMsgCtx)));
            properties.put(OIDCConstants.Event.SERVICE_PROVIDER, OAuth2Util.getServiceProvider(
                    tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId(), issuerTenant).getApplicationName());
            properties.put(OIDCConstants.Event.ISSUER_ORGANIZATION_ID, issuerOrganizationId);
            properties.put(OIDCConstants.Event.ACCESSING_ORGANIZATION_ID, accessingOrganizationId);
            properties.put(OIDCConstants.Event.TOKEN_ID, tokReqMsgCtx.getProperty(OIDCConstants.TOKEN_ID));

            properties.put(IdentityEventConstants.EventProperty.IAT, tokReqMsgCtx.getAccessTokenIssuedTime());
            properties.put(IdentityEventConstants.EventProperty.JTI, tokReqMsgCtx.getJWTID());
            properties.put(IdentityEventConstants.EventProperty.GRANT_TYPE, oAuth2AccessTokenReqDTO.getGrantType());
            properties.put(OIDCConstants.Event.APP_RESIDENT_TENANT_ID, IdentityTenantUtil.getLoginTenantId());

            if (tokReqMsgCtx.getProperty(APP_DAO) != null &&
                    tokReqMsgCtx.getProperty(APP_DAO) instanceof OAuthAppDO) {
                OAuthAppDO oAuthAppDO = (OAuthAppDO) tokReqMsgCtx.getProperty(APP_DAO);
                properties.put(IdentityEventConstants.EventProperty.APPLICATION_ID, oAuthAppDO.getId());
                properties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME, oAuthAppDO.getApplicationName());
                properties.put(IdentityEventConstants.EventProperty.CONSUMER_KEY, oAuthAppDO.getOauthConsumerKey());
            }
        }

        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN,
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain());
        properties.put(IdentityEventConstants.EventProperty.TENANT_ID,
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId());

        Event identityMgtEvent = new Event(IdentityEventConstants.Event.POST_ISSUE_ACCESS_TOKEN_V2, properties);

        try {
            OAuth2ServiceComponentHolder.getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException e) {
            LOG.error("Error occurred publishing event " + IdentityEventConstants.Event.POST_ISSUE_ACCESS_TOKEN_V2, e);
        }
    }

    private static Boolean existingTokenUsed(OAuthTokenReqMessageContext tokReqMsgCtx) {

        Boolean existingTokenUsed = (Boolean) tokReqMsgCtx.getProperty(EXISTING_TOKEN_USED);
        if (existingTokenUsed == null) {
            existingTokenUsed = false;
        }
        return existingTokenUsed;
    }
}
