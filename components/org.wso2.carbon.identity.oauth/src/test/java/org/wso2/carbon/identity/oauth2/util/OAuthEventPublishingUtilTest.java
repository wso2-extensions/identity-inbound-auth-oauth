/*
 * Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.util;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.testng.MockitoTestNGListener;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth.internal.util.AccessTokenEventUtil;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;

import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.openMocks;

@Listeners(MockitoTestNGListener.class)
@WithCarbonHome
public class OAuthEventPublishingUtilTest {

    @Mock
    OAuthTokenReqMessageContext tokReqMsgCtx;

    @Mock
    OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO;

    @Mock
    OAuth2AccessTokenRespDTO oAuth2AccessTokenRespDTO;

    @Mock
    AuthenticatedUser authorizedUser;

    @Mock
    OAuthAppDO oAuthAppDO;

    @Mock
    OauthTokenIssuer tokenIssuer;

    @Mock
    IdentityEventService identityEventService;

    @Mock
    OrganizationManager organizationManager;

    @BeforeMethod
    public void setUp() throws UserIdNotFoundException {

        openMocks(this);
        when(oAuth2AccessTokenReqDTO.getClientId()).thenReturn("test-client-id");
        when(oAuth2AccessTokenReqDTO.getGrantType()).thenReturn("authorization_code");
        when(oAuth2AccessTokenReqDTO.getTenantDomain()).thenReturn("carbon.super");

        when(tokReqMsgCtx.getAuthorizedUser()).thenReturn(authorizedUser);
        when(authorizedUser.getUserId()).thenReturn("user-id");
        when(authorizedUser.getUserName()).thenReturn("john");
        when(authorizedUser.getUserStoreDomain()).thenReturn("PRIMARY");
        when(authorizedUser.isOrganizationUser()).thenReturn(true);
        when(authorizedUser.getUserResidentOrganization()).thenReturn("resident-org-id");
        when(authorizedUser.getAccessingOrganization()).thenReturn("accessing-org-id");

        when(tokReqMsgCtx.getAccessTokenIssuedTime()).thenReturn(System.currentTimeMillis());
        when(tokReqMsgCtx.getJWTID()).thenReturn("jti-123");
        when(tokReqMsgCtx.getProperty(OAuthConstants.UserType.USER_TYPE)).thenReturn("APPLICATION_USER");
        when(tokReqMsgCtx.getProperty("OAuthAppDO")).thenReturn(oAuthAppDO);
        when(tokReqMsgCtx.getProperty(OAuthConstants.OIDCConfigProperties.EXISTING_TOKEN_USED))
                .thenReturn(null);

        when(oAuthAppDO.getId()).thenReturn(123);
        when(oAuthAppDO.getApplicationName()).thenReturn("TestApp");
        when(oAuthAppDO.getOauthConsumerKey()).thenReturn("test-client-id");

        when(tokenIssuer.getAccessTokenType()).thenReturn("Opaque");

        when(oAuth2AccessTokenRespDTO.getTokenId()).thenReturn("token-id-123");
    }

    @Test
    public void testPublishTokenIssueEvent() throws UserIdNotFoundException, IdentityEventException,
            OrganizationManagementException {

        try (MockedStatic<OAuth2Util> mockedOAuth2Util = Mockito.mockStatic(OAuth2Util.class);
             MockedStatic<OAuth2ServiceComponentHolder> mockedServiceHolder = Mockito.mockStatic(
                     OAuth2ServiceComponentHolder.class);
             MockedStatic<OAuthComponentServiceHolder> mockedOAuthComponentHolder = Mockito.mockStatic(
                     OAuthComponentServiceHolder.class);
             MockedStatic<OrganizationManagementUtil> mockedOrgManagementUtil = Mockito.mockStatic(
                     OrganizationManagementUtil.class);
             MockedStatic<PrivilegedCarbonContext> mockedCarbonContext = Mockito.mockStatic(
                     PrivilegedCarbonContext.class);
             MockedStatic<IdentityTenantUtil> mockedTenantUtil = Mockito.mockStatic(
                     IdentityTenantUtil.class)) {

            mockedOAuth2Util.when(() -> OAuth2Util.getOAuthTokenIssuerForOAuthApp(anyString()))
                    .thenReturn(tokenIssuer);
            when(tokenIssuer.getAccessTokenType()).thenReturn("Opaque");

            mockedServiceHolder.when(OAuth2ServiceComponentHolder::getIdentityEventService)
                    .thenReturn(identityEventService);

            OAuthComponentServiceHolder oAuthComponentServiceHolder = mock(OAuthComponentServiceHolder.class);
            mockedOAuthComponentHolder.when(OAuthComponentServiceHolder::getInstance)
                    .thenReturn(oAuthComponentServiceHolder);
            when(oAuthComponentServiceHolder.getOrganizationManager()).thenReturn(organizationManager);
            when(organizationManager.resolveOrganizationId("carbon.super")).thenReturn("issuer-org-id");

            // Mock OrganizationManagementUtil for root org resolution
            mockedOrgManagementUtil.when(() -> OrganizationManagementUtil.getRootOrgTenantDomainBySubOrgTenantDomain(
                    "carbon.super")).thenReturn("carbon.super");

            // Mock OAuth2Util.getServiceProvider
            org.wso2.carbon.identity.application.common.model.ServiceProvider serviceProvider =
                    mock(org.wso2.carbon.identity.application.common.model.ServiceProvider.class);
            when(serviceProvider.getApplicationName()).thenReturn("TestApp");
            mockedOAuth2Util.when(() -> OAuth2Util.getServiceProvider(anyString(), anyString()))
                    .thenReturn(serviceProvider);

            PrivilegedCarbonContext carbonContext = mock(PrivilegedCarbonContext.class);
            mockedCarbonContext.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                    .thenReturn(carbonContext);
            when(carbonContext.getTenantDomain()).thenReturn("carbon.super");
            when(carbonContext.getTenantId()).thenReturn(-1234);

            mockedTenantUtil.when(IdentityTenantUtil::getLoginTenantId).thenReturn(1);

            AccessTokenEventUtil.publishTokenIssueEvent(tokReqMsgCtx, oAuth2AccessTokenReqDTO,
                    oAuth2AccessTokenRespDTO);

            ArgumentCaptor<Event> eventCaptor = ArgumentCaptor.forClass(Event.class);
            verify(identityEventService).handleEvent(eventCaptor.capture());

            Event event = eventCaptor.getValue();
            assertEquals(IdentityEventConstants.Event.POST_ISSUE_ACCESS_TOKEN_V2, event.getEventName());

            Map<String, Object> properties = event.getEventProperties();

            // Test existing properties
            assertEquals("user-id", properties.get(IdentityEventConstants.EventProperty.USER_ID));
            assertEquals("john", properties.get(IdentityEventConstants.EventProperty.USER_NAME));
            assertEquals("PRIMARY", properties.get(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN));
            assertEquals("Opaque", properties.get(IdentityEventConstants.EventProperty.TOKEN_TYPE));
            assertEquals("TestApp", properties.get(IdentityEventConstants.EventProperty.APPLICATION_NAME));
            assertEquals("carbon.super", properties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));
            assertEquals(-1234, properties.get(IdentityEventConstants.EventProperty.TENANT_ID));
            assertEquals("authorization_code", properties.get(IdentityEventConstants.EventProperty.GRANT_TYPE));
            assertEquals("test-client-id", properties.get(OAuthConstants.EventProperty.CLIENT_ID));
            assertEquals(123, properties.get(IdentityEventConstants.EventProperty.APPLICATION_ID));
            assertEquals("test-client-id", properties.get(IdentityEventConstants.EventProperty.CONSUMER_KEY));
            assertEquals("jti-123", properties.get(IdentityEventConstants.EventProperty.JTI));

            // Test newly added properties
            assertEquals(true, properties.get(IdentityEventConstants.EventProperty.IS_ORGANIZATION_USER));
            assertEquals("resident-org-id",
                    properties.get(IdentityEventConstants.EventProperty.USER_RESIDENT_ORGANIZATION_ID));
            assertEquals("issuer-org-id",
                    properties.get(OAuthConstants.EventProperty.ISSUER_ORGANIZATION_ID));
            assertEquals("accessing-org-id",
                    properties.get(OAuthConstants.EventProperty.ACCESSING_ORGANIZATION_ID));
            assertEquals("APPLICATION_USER", properties.get(OAuthConstants.EventProperty.USER_TYPE));
            assertEquals("token-id-123", properties.get(OAuthConstants.EventProperty.TOKEN_ID));
            assertEquals(1, properties.get(OAuthConstants.EventProperty.APP_RESIDENT_TENANT_ID));
            assertFalse((Boolean) properties.get(OAuthConstants.EventProperty.EXISTING_TOKEN_USED));
            assertEquals("carbon.super",
                    properties.get(OAuthConstants.EventProperty.ROOT_TENANT_DOMAIN));
            assertEquals("TestApp", properties.get(OAuthConstants.EventProperty.SERVICE_PROVIDER));
        }
    }

    @Test
    public void testPublishTokenIssueEventWithExistingTokenUsed() throws UserIdNotFoundException,
            IdentityEventException, OrganizationManagementException {

        // Override the setup to set EXISTING_TOKEN_USED to true
        when(tokReqMsgCtx.getProperty(OAuthConstants.OIDCConfigProperties.EXISTING_TOKEN_USED))
                .thenReturn(true);

        try (MockedStatic<OAuth2Util> mockedOAuth2Util = Mockito.mockStatic(OAuth2Util.class);
             MockedStatic<OAuth2ServiceComponentHolder> mockedServiceHolder = Mockito.mockStatic(
                     OAuth2ServiceComponentHolder.class);
             MockedStatic<OAuthComponentServiceHolder> mockedOAuthComponentHolder = Mockito.mockStatic(
                     OAuthComponentServiceHolder.class);
             MockedStatic<OrganizationManagementUtil> mockedOrgManagementUtil = Mockito.mockStatic(
                     OrganizationManagementUtil.class);
             MockedStatic<PrivilegedCarbonContext> mockedCarbonContext = Mockito.mockStatic(
                     PrivilegedCarbonContext.class);
             MockedStatic<IdentityTenantUtil> mockedTenantUtil = Mockito.mockStatic(
                     IdentityTenantUtil.class)) {

            mockedOAuth2Util.when(() -> OAuth2Util.getOAuthTokenIssuerForOAuthApp(anyString()))
                    .thenReturn(tokenIssuer);
            when(tokenIssuer.getAccessTokenType()).thenReturn("Opaque");

            mockedServiceHolder.when(OAuth2ServiceComponentHolder::getIdentityEventService)
                    .thenReturn(identityEventService);

            OAuthComponentServiceHolder oAuthComponentServiceHolder = mock(OAuthComponentServiceHolder.class);
            mockedOAuthComponentHolder.when(OAuthComponentServiceHolder::getInstance)
                    .thenReturn(oAuthComponentServiceHolder);
            when(oAuthComponentServiceHolder.getOrganizationManager()).thenReturn(organizationManager);
            when(organizationManager.resolveOrganizationId("carbon.super")).thenReturn("issuer-org-id");

            mockedOrgManagementUtil.when(() -> OrganizationManagementUtil.getRootOrgTenantDomainBySubOrgTenantDomain(
                    "carbon.super")).thenReturn("carbon.super");

            org.wso2.carbon.identity.application.common.model.ServiceProvider serviceProvider =
                    mock(org.wso2.carbon.identity.application.common.model.ServiceProvider.class);
            when(serviceProvider.getApplicationName()).thenReturn("TestApp");
            mockedOAuth2Util.when(() -> OAuth2Util.getServiceProvider(anyString(), anyString()))
                    .thenReturn(serviceProvider);

            PrivilegedCarbonContext carbonContext = mock(PrivilegedCarbonContext.class);
            mockedCarbonContext.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                    .thenReturn(carbonContext);
            when(carbonContext.getTenantDomain()).thenReturn("carbon.super");
            when(carbonContext.getTenantId()).thenReturn(-1234);

            mockedTenantUtil.when(IdentityTenantUtil::getLoginTenantId).thenReturn(1);

            AccessTokenEventUtil.publishTokenIssueEvent(tokReqMsgCtx, oAuth2AccessTokenReqDTO,
                    oAuth2AccessTokenRespDTO);

            ArgumentCaptor<Event> eventCaptor = ArgumentCaptor.forClass(Event.class);
            verify(identityEventService).handleEvent(eventCaptor.capture());

            Event event = eventCaptor.getValue();
            assertEquals(IdentityEventConstants.Event.POST_ISSUE_ACCESS_TOKEN_V2, event.getEventName());

            Map<String, Object> properties = event.getEventProperties();

            // Verify EXISTING_TOKEN_USED is true
            assertEquals(true, properties.get(OAuthConstants.EventProperty.EXISTING_TOKEN_USED));

            // Verify other properties are still correctly set
            assertEquals("user-id", properties.get(IdentityEventConstants.EventProperty.USER_ID));
            assertEquals("authorization_code", properties.get(IdentityEventConstants.EventProperty.GRANT_TYPE));
            assertEquals("test-client-id", properties.get(OAuthConstants.EventProperty.CLIENT_ID));
        }
    }

    @Test
    public void testPublishTokenIssueEventWithUserNameNotPresent() throws UserIdNotFoundException,
            IdentityEventException, OrganizationManagementException {

        // Override the setup to set userName to null
        when(authorizedUser.getUserName()).thenReturn(null);

        try (MockedStatic<OAuth2Util> mockedOAuth2Util = Mockito.mockStatic(OAuth2Util.class);
             MockedStatic<OAuth2ServiceComponentHolder> mockedServiceHolder = Mockito.mockStatic(
                     OAuth2ServiceComponentHolder.class);
             MockedStatic<OAuthComponentServiceHolder> mockedOAuthComponentHolder = Mockito.mockStatic(
                     OAuthComponentServiceHolder.class);
             MockedStatic<OrganizationManagementUtil> mockedOrgManagementUtil = Mockito.mockStatic(
                     OrganizationManagementUtil.class);
             MockedStatic<PrivilegedCarbonContext> mockedCarbonContext = Mockito.mockStatic(
                     PrivilegedCarbonContext.class);
             MockedStatic<IdentityTenantUtil> mockedTenantUtil = Mockito.mockStatic(
                     IdentityTenantUtil.class)) {

            mockedOAuth2Util.when(() -> OAuth2Util.getOAuthTokenIssuerForOAuthApp(anyString()))
                    .thenReturn(tokenIssuer);
            when(tokenIssuer.getAccessTokenType()).thenReturn("Opaque");

            mockedServiceHolder.when(OAuth2ServiceComponentHolder::getIdentityEventService)
                    .thenReturn(identityEventService);

            OAuthComponentServiceHolder oAuthComponentServiceHolder = mock(OAuthComponentServiceHolder.class);
            mockedOAuthComponentHolder.when(OAuthComponentServiceHolder::getInstance)
                    .thenReturn(oAuthComponentServiceHolder);
            when(oAuthComponentServiceHolder.getOrganizationManager()).thenReturn(organizationManager);
            when(organizationManager.resolveOrganizationId("carbon.super")).thenReturn("issuer-org-id");

            mockedOrgManagementUtil.when(() -> OrganizationManagementUtil.getRootOrgTenantDomainBySubOrgTenantDomain(
                    "carbon.super")).thenReturn("carbon.super");

            org.wso2.carbon.identity.application.common.model.ServiceProvider serviceProvider =
                    mock(org.wso2.carbon.identity.application.common.model.ServiceProvider.class);
            when(serviceProvider.getApplicationName()).thenReturn("TestApp");
            mockedOAuth2Util.when(() -> OAuth2Util.getServiceProvider(anyString(), anyString()))
                    .thenReturn(serviceProvider);

            PrivilegedCarbonContext carbonContext = mock(PrivilegedCarbonContext.class);
            mockedCarbonContext.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                    .thenReturn(carbonContext);
            when(carbonContext.getTenantDomain()).thenReturn("carbon.super");
            when(carbonContext.getTenantId()).thenReturn(-1234);

            mockedTenantUtil.when(IdentityTenantUtil::getLoginTenantId).thenReturn(1);

            AccessTokenEventUtil.publishTokenIssueEvent(tokReqMsgCtx, oAuth2AccessTokenReqDTO,
                    oAuth2AccessTokenRespDTO);

            ArgumentCaptor<Event> eventCaptor = ArgumentCaptor.forClass(Event.class);
            verify(identityEventService).handleEvent(eventCaptor.capture());

            Event event = eventCaptor.getValue();
            assertEquals(IdentityEventConstants.Event.POST_ISSUE_ACCESS_TOKEN_V2, event.getEventName());

            Map<String, Object> properties = event.getEventProperties();

            // Verify USER_NAME is null when not present
            assertNull(properties.get(IdentityEventConstants.EventProperty.USER_NAME));

            // Verify other user-related properties are still set
            assertEquals("user-id", properties.get(IdentityEventConstants.EventProperty.USER_ID));
            assertEquals("PRIMARY", properties.get(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN));
            assertEquals(true, properties.get(IdentityEventConstants.EventProperty.IS_ORGANIZATION_USER));

            // Verify non-user properties are correctly set
            assertEquals("authorization_code", properties.get(IdentityEventConstants.EventProperty.GRANT_TYPE));
            assertEquals("test-client-id", properties.get(OAuthConstants.EventProperty.CLIENT_ID));
            assertFalse((Boolean) properties.get(OAuthConstants.EventProperty.EXISTING_TOKEN_USED));
        }
    }

    @Test
    public void testPublishTokenIssueEventWithSubOrgTenantDomain() throws UserIdNotFoundException,
            IdentityEventException, OrganizationManagementException {

        // Override the setup to use a sub-organization tenant domain (not carbon.super)
        when(oAuth2AccessTokenReqDTO.getTenantDomain()).thenReturn("sub.example.com");

        try (MockedStatic<OAuth2Util> mockedOAuth2Util = Mockito.mockStatic(OAuth2Util.class);
             MockedStatic<OAuth2ServiceComponentHolder> mockedServiceHolder = Mockito.mockStatic(
                     OAuth2ServiceComponentHolder.class);
             MockedStatic<OAuthComponentServiceHolder> mockedOAuthComponentHolder = Mockito.mockStatic(
                     OAuthComponentServiceHolder.class);
             MockedStatic<OrganizationManagementUtil> mockedOrgManagementUtil = Mockito.mockStatic(
                     OrganizationManagementUtil.class);
             MockedStatic<PrivilegedCarbonContext> mockedCarbonContext = Mockito.mockStatic(
                     PrivilegedCarbonContext.class);
             MockedStatic<IdentityTenantUtil> mockedTenantUtil = Mockito.mockStatic(
                     IdentityTenantUtil.class)) {

            mockedOAuth2Util.when(() -> OAuth2Util.getOAuthTokenIssuerForOAuthApp(anyString()))
                    .thenReturn(tokenIssuer);
            when(tokenIssuer.getAccessTokenType()).thenReturn("Opaque");

            mockedServiceHolder.when(OAuth2ServiceComponentHolder::getIdentityEventService)
                    .thenReturn(identityEventService);

            OAuthComponentServiceHolder oAuthComponentServiceHolder = mock(OAuthComponentServiceHolder.class);
            mockedOAuthComponentHolder.when(OAuthComponentServiceHolder::getInstance)
                    .thenReturn(oAuthComponentServiceHolder);
            when(oAuthComponentServiceHolder.getOrganizationManager()).thenReturn(organizationManager);
            when(organizationManager.resolveOrganizationId("sub.example.com")).thenReturn("sub-org-id");

            // Mock getRootOrgTenantDomainBySubOrgTenantDomain to return a root org domain
            // for the non-carbon.super (else) branch
            mockedOrgManagementUtil.when(() -> OrganizationManagementUtil.getRootOrgTenantDomainBySubOrgTenantDomain(
                    "sub.example.com")).thenReturn("root.example.com");

            org.wso2.carbon.identity.application.common.model.ServiceProvider serviceProvider =
                    mock(org.wso2.carbon.identity.application.common.model.ServiceProvider.class);
            when(serviceProvider.getApplicationName()).thenReturn("TestApp");
            mockedOAuth2Util.when(() -> OAuth2Util.getServiceProvider(anyString(), anyString()))
                    .thenReturn(serviceProvider);

            PrivilegedCarbonContext carbonContext = mock(PrivilegedCarbonContext.class);
            mockedCarbonContext.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                    .thenReturn(carbonContext);
            when(carbonContext.getTenantDomain()).thenReturn("sub.example.com");
            when(carbonContext.getTenantId()).thenReturn(-1234);

            mockedTenantUtil.when(IdentityTenantUtil::getLoginTenantId).thenReturn(1);

            AccessTokenEventUtil.publishTokenIssueEvent(tokReqMsgCtx, oAuth2AccessTokenReqDTO,
                    oAuth2AccessTokenRespDTO);

            ArgumentCaptor<Event> eventCaptor = ArgumentCaptor.forClass(Event.class);
            verify(identityEventService).handleEvent(eventCaptor.capture());

            Event event = eventCaptor.getValue();
            Map<String, Object> properties = event.getEventProperties();

            // The root org tenant domain must be resolved via getRootOrgTenantDomainBySubOrgTenantDomain
            assertEquals("root.example.com",
                    properties.get(OAuthConstants.EventProperty.ROOT_TENANT_DOMAIN));
            assertEquals("sub-org-id",
                    properties.get(OAuthConstants.EventProperty.ISSUER_ORGANIZATION_ID));
        }
    }

    @Test
    public void testPublishTokenIssueEventWithNullTenantDomain() throws UserIdNotFoundException,
            IdentityEventException, OrganizationManagementException {

        // Override the setup so that getTenantDomain() returns null
        when(oAuth2AccessTokenReqDTO.getTenantDomain()).thenReturn(null);

        try (MockedStatic<OAuth2Util> mockedOAuth2Util = Mockito.mockStatic(OAuth2Util.class);
             MockedStatic<OAuth2ServiceComponentHolder> mockedServiceHolder = Mockito.mockStatic(
                     OAuth2ServiceComponentHolder.class);
             MockedStatic<OAuthComponentServiceHolder> mockedOAuthComponentHolder = Mockito.mockStatic(
                     OAuthComponentServiceHolder.class);
             MockedStatic<OrganizationManagementUtil> mockedOrgManagementUtil = Mockito.mockStatic(
                     OrganizationManagementUtil.class);
             MockedStatic<PrivilegedCarbonContext> mockedCarbonContext = Mockito.mockStatic(
                     PrivilegedCarbonContext.class);
             MockedStatic<IdentityTenantUtil> mockedTenantUtil = Mockito.mockStatic(
                     IdentityTenantUtil.class)) {

            mockedOAuth2Util.when(() -> OAuth2Util.getOAuthTokenIssuerForOAuthApp(anyString()))
                    .thenReturn(tokenIssuer);
            when(tokenIssuer.getAccessTokenType()).thenReturn("Opaque");

            mockedServiceHolder.when(OAuth2ServiceComponentHolder::getIdentityEventService)
                    .thenReturn(identityEventService);

            OAuthComponentServiceHolder oAuthComponentServiceHolder = mock(OAuthComponentServiceHolder.class);
            mockedOAuthComponentHolder.when(OAuthComponentServiceHolder::getInstance)
                    .thenReturn(oAuthComponentServiceHolder);
            when(oAuthComponentServiceHolder.getOrganizationManager()).thenReturn(organizationManager);

            PrivilegedCarbonContext carbonContext = mock(PrivilegedCarbonContext.class);
            mockedCarbonContext.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                    .thenReturn(carbonContext);
            when(carbonContext.getTenantDomain()).thenReturn("carbon.super");
            when(carbonContext.getTenantId()).thenReturn(-1234);

            mockedTenantUtil.when(IdentityTenantUtil::getLoginTenantId).thenReturn(1);

            AccessTokenEventUtil.publishTokenIssueEvent(tokReqMsgCtx, oAuth2AccessTokenReqDTO,
                    oAuth2AccessTokenRespDTO);

            ArgumentCaptor<Event> eventCaptor = ArgumentCaptor.forClass(Event.class);
            verify(identityEventService).handleEvent(eventCaptor.capture());

            Event event = eventCaptor.getValue();
            Map<String, Object> properties = event.getEventProperties();

            // When tenant domain is null the inner if block is skipped; rootOrgTenantDomain stays empty
            assertEquals("", properties.get(OAuthConstants.EventProperty.ROOT_TENANT_DOMAIN));

            // getRootOrgTenantDomainBySubOrgTenantDomain must never be called
            mockedOrgManagementUtil.verify(
                    () -> OrganizationManagementUtil.getRootOrgTenantDomainBySubOrgTenantDomain(anyString()),
                    Mockito.never());
        }
    }

    @Test
    public void testPublishTokenIssueEventWithRootOrgResolutionException() throws UserIdNotFoundException,
            IdentityEventException, OrganizationManagementException {

        // Use a sub-org tenant domain so the else branch is taken
        when(oAuth2AccessTokenReqDTO.getTenantDomain()).thenReturn("sub.example.com");

        try (MockedStatic<OAuth2Util> mockedOAuth2Util = Mockito.mockStatic(OAuth2Util.class);
             MockedStatic<OAuth2ServiceComponentHolder> mockedServiceHolder = Mockito.mockStatic(
                     OAuth2ServiceComponentHolder.class);
             MockedStatic<OAuthComponentServiceHolder> mockedOAuthComponentHolder = Mockito.mockStatic(
                     OAuthComponentServiceHolder.class);
             MockedStatic<OrganizationManagementUtil> mockedOrgManagementUtil = Mockito.mockStatic(
                     OrganizationManagementUtil.class);
             MockedStatic<PrivilegedCarbonContext> mockedCarbonContext = Mockito.mockStatic(
                     PrivilegedCarbonContext.class);
             MockedStatic<IdentityTenantUtil> mockedTenantUtil = Mockito.mockStatic(
                     IdentityTenantUtil.class)) {

            mockedOAuth2Util.when(() -> OAuth2Util.getOAuthTokenIssuerForOAuthApp(anyString()))
                    .thenReturn(tokenIssuer);
            when(tokenIssuer.getAccessTokenType()).thenReturn("Opaque");

            mockedServiceHolder.when(OAuth2ServiceComponentHolder::getIdentityEventService)
                    .thenReturn(identityEventService);

            OAuthComponentServiceHolder oAuthComponentServiceHolder = mock(OAuthComponentServiceHolder.class);
            mockedOAuthComponentHolder.when(OAuthComponentServiceHolder::getInstance)
                    .thenReturn(oAuthComponentServiceHolder);
            when(oAuthComponentServiceHolder.getOrganizationManager()).thenReturn(organizationManager);
            when(organizationManager.resolveOrganizationId("sub.example.com")).thenReturn("sub-org-id");

            // Simulate an exception thrown by getRootOrgTenantDomainBySubOrgTenantDomain
            mockedOrgManagementUtil.when(() -> OrganizationManagementUtil.getRootOrgTenantDomainBySubOrgTenantDomain(
                    "sub.example.com")).thenThrow(
                    new OrganizationManagementException("Error resolving root org"));

            org.wso2.carbon.identity.application.common.model.ServiceProvider serviceProvider =
                    mock(org.wso2.carbon.identity.application.common.model.ServiceProvider.class);
            when(serviceProvider.getApplicationName()).thenReturn("TestApp");
            mockedOAuth2Util.when(() -> OAuth2Util.getServiceProvider(anyString(), anyString()))
                    .thenReturn(serviceProvider);

            PrivilegedCarbonContext carbonContext = mock(PrivilegedCarbonContext.class);
            mockedCarbonContext.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                    .thenReturn(carbonContext);
            when(carbonContext.getTenantDomain()).thenReturn("sub.example.com");
            when(carbonContext.getTenantId()).thenReturn(-1234);

            mockedTenantUtil.when(IdentityTenantUtil::getLoginTenantId).thenReturn(1);

            // The event should still be published despite the exception (error is logged and swallowed)
            AccessTokenEventUtil.publishTokenIssueEvent(tokReqMsgCtx, oAuth2AccessTokenReqDTO,
                    oAuth2AccessTokenRespDTO);

            ArgumentCaptor<Event> eventCaptor = ArgumentCaptor.forClass(Event.class);
            verify(identityEventService).handleEvent(eventCaptor.capture());

            Event event = eventCaptor.getValue();
            Map<String, Object> properties = event.getEventProperties();

            // rootOrgTenantDomain stays empty because the exception was caught
            assertEquals("", properties.get(OAuthConstants.EventProperty.ROOT_TENANT_DOMAIN));
        }
    }
}
