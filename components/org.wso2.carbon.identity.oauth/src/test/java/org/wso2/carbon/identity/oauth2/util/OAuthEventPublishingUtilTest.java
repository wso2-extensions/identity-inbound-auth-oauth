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
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
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
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.openMocks;
import static org.wso2.carbon.identity.openidconnect.OIDCConstants.Event.EXISTING_TOKEN_USED;

@Listeners(MockitoTestNGListener.class)
@WithCarbonHome
public class OAuthEventPublishingUtilTest {

    private final int testAppResidentTenantId = 11;

    @Mock
    OAuthTokenReqMessageContext tokReqMsgCtx;

    @Mock
    OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO;

    @Mock
    AuthenticatedUser authorizedUser;

    @Mock
    OAuthAppDO oAuthAppDO;

    @Mock
    OauthTokenIssuer tokenIssuer;

    @Mock
    IdentityEventService identityEventService;

    @Mock
    LocalAndOutboundAuthenticationConfig localAndOutboundAuthenticationConfig;

    @Mock
    ServiceProvider sp;

    @Mock
    OAuthComponentServiceHolder oAuthComponentServiceHolder;

    @Mock
    OrganizationManager organizationManager;

    @BeforeMethod
    public void setUp() throws UserIdNotFoundException, IdentityApplicationManagementException,
            OrganizationManagementException {

        openMocks(this);
        when(oAuth2AccessTokenReqDTO.getClientId()).thenReturn("test-client-id");
        when(oAuth2AccessTokenReqDTO.getGrantType()).thenReturn("authorization_code");
        when(oAuth2AccessTokenReqDTO.getTenantDomain()).thenReturn("issuer-tenant-domain");

        when(tokReqMsgCtx.getAuthorizedUser()).thenReturn(authorizedUser);
        when(authorizedUser.getUserId()).thenReturn("user-id");
        when(authorizedUser.getUserName()).thenReturn("john");
        when(authorizedUser.getUserStoreDomain()).thenReturn("PRIMARY");

        when(tokReqMsgCtx.getAccessTokenIssuedTime()).thenReturn(System.currentTimeMillis());
        when(tokReqMsgCtx.getJWTID()).thenReturn("jti-123");

        when(tokReqMsgCtx.getProperty(anyString())).thenReturn(oAuthAppDO);
        when(oAuthAppDO.getId()).thenReturn(123);
        when(oAuthAppDO.getApplicationName()).thenReturn("TestApp");
        when(oAuthAppDO.getOauthConsumerKey()).thenReturn("test-client-id");

        when(tokenIssuer.getAccessTokenType()).thenReturn("Opaque");

        when(tokReqMsgCtx.getProperty(OAuthConstants.UserType.USER_TYPE)).thenReturn("APPLICATION_USER");
        when(tokReqMsgCtx.getOauth2AccessTokenReqDTO()).thenReturn(oAuth2AccessTokenReqDTO);
        when(tokReqMsgCtx.getProperty(EXISTING_TOKEN_USED)).thenReturn(Boolean.FALSE);

        when(oAuthComponentServiceHolder.getOrganizationManager()).thenReturn(organizationManager);
        when(organizationManager.resolveOrganizationId(anyString())).thenReturn("test-org-id");
    }

    @Test
    public void testPublishTokenIssueEvent() throws UserIdNotFoundException, IdentityEventException,
            IdentityOAuth2Exception, OrganizationManagementException {

        try (MockedStatic<OAuth2Util> mockedOAuth2Util = Mockito.mockStatic(OAuth2Util.class);
             MockedStatic<OAuth2ServiceComponentHolder> mockedServiceHolder = Mockito.mockStatic(
                     OAuth2ServiceComponentHolder.class);
             MockedStatic<PrivilegedCarbonContext> mockedCarbonContext = Mockito.mockStatic(
                     PrivilegedCarbonContext.class);
             MockedStatic<OAuthComponentServiceHolder> mockedOAuthComponentServiceHolder = Mockito.mockStatic(
                     OAuthComponentServiceHolder.class);
             MockedStatic<IdentityTenantUtil> mockedIdentityTenantUtil = Mockito.mockStatic(
                     IdentityTenantUtil.class)
             ) {

            mockedOAuth2Util.when(() -> OAuth2Util.getOAuthTokenIssuerForOAuthApp(anyString()))
                    .thenReturn(tokenIssuer);
            mockedOAuth2Util.when(() -> OAuth2Util.getServiceProvider(anyString(), anyString()))
                    .thenReturn(sp);
            when(tokenIssuer.getAccessTokenType()).thenReturn("Opaque");

            mockedServiceHolder.when(OAuth2ServiceComponentHolder::getIdentityEventService)
                    .thenReturn(identityEventService);

            mockedOAuthComponentServiceHolder.when(OAuthComponentServiceHolder::getInstance)
                    .thenReturn(oAuthComponentServiceHolder);
            mockedIdentityTenantUtil.when(IdentityTenantUtil::getLoginTenantId).thenReturn(testAppResidentTenantId);

            PrivilegedCarbonContext carbonContext = mock(PrivilegedCarbonContext.class);
            mockedCarbonContext.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                    .thenReturn(carbonContext);
            when(carbonContext.getTenantDomain()).thenReturn("carbon.super");
            when(carbonContext.getTenantId()).thenReturn(-1234);

            AccessTokenEventUtil.publishTokenIssueEvent(tokReqMsgCtx, oAuth2AccessTokenReqDTO);

            ArgumentCaptor<Event> eventCaptor = ArgumentCaptor.forClass(Event.class);
            verify(identityEventService).handleEvent(eventCaptor.capture());

            Event event = eventCaptor.getValue();
            assertEquals(IdentityEventConstants.Event.POST_ISSUE_ACCESS_TOKEN_V2, event.getEventName());

            Map<String, Object> properties = event.getEventProperties();
            assertEquals("user-id", properties.get(IdentityEventConstants.EventProperty.USER_ID));
            assertEquals("Opaque", properties.get(IdentityEventConstants.EventProperty.TOKEN_TYPE));
            assertEquals("TestApp", properties.get(IdentityEventConstants.EventProperty.APPLICATION_NAME));
            assertEquals("carbon.super", properties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));
        }
    }
}
