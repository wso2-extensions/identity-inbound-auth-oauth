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

package org.wso2.carbon.identity.oauth.endpoint.authz;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.endpoint.message.OAuthMessage;
import org.wso2.carbon.identity.oauth.endpoint.util.TestOAuthEndpointBase;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationContext;
import org.wso2.carbon.identity.oauth2.impersonation.models.ImpersonationRequestDTO;
import org.wso2.carbon.identity.oauth2.impersonation.services.ImpersonationMgtService;
import org.wso2.carbon.identity.oauth2.impersonation.services.ImpersonationMgtServiceImpl;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.CODE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.REQUESTED_SUBJECT;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.SUBJECT_TOKEN;
import static org.wso2.carbon.identity.oauth2.impersonation.utils.Constants.IMPERSONATION_SCOPE_NAME;

@WithCarbonHome
public class OAuth2AuthzEndpointImpersonationTest extends TestOAuthEndpointBase {

    @DataProvider
    public Object[][] getHandleSessionImpersonationData() {
        return new Object[][]{
                // response type, existingImpersonatedUserId, impersonatedUserIdInReq,
                // rejectImpersonation, ssoImpersonation, validImpersonation
                {SUBJECT_TOKEN, "impersonatedUserId", "impersonatedUserId", false, false, true},
                {SUBJECT_TOKEN, null, "impersonatedUserId", false, false, true},
                {SUBJECT_TOKEN, "impersonatedUserId", "otherImpersonatedUserId", true, false, false},
                // Invalid impersonation request
                {SUBJECT_TOKEN, "impersonatedUserId", null, false, false, false},
                {SUBJECT_TOKEN, null, null, false, false, false},

                // SSO cases.
                {CODE, "impersonatedUserId", "impersonatedUserId", false, true, true},
                {CODE, "impersonatedUserId", "OtherImpersonatedUserId", false, true, false},
        };
    }

    @Test(dataProvider = "getHandleSessionImpersonationData")
    public void testHandleSessionImpersonation(String responseType, String existingImpersonatedUserId,
                                     String impersonatedUserIdInReq, boolean rejectImpersonation,
                                     boolean ssoImpersonation, boolean validImpersonation) throws Exception {

        String dummyClientId = "dummyClientId";

        try (MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
            MockedStatic<IdentityTenantUtil> identityTenantUtil = mockStatic(IdentityTenantUtil.class);
            MockedStatic<AppInfoCache> appInfoCache = mockStatic(AppInfoCache.class);
            MockedStatic<OAuth2ServiceComponentHolder> oAuth2ServiceComponentHolder =
                     mockStatic(OAuth2ServiceComponentHolder.class, Mockito.CALLS_REAL_METHODS)) {

            Cookie authCookie = mock(Cookie.class);
            SessionContext sessionContext = mock(SessionContext.class);
            OAuthMessage oAuthMessage = mock(OAuthMessage.class);
            OAuth2Parameters oAuth2Parameters = mock(OAuth2Parameters.class);
            AuthenticationResult authenticationResult = new AuthenticationResult();
            HttpServletRequest mockRequest = mock(HttpServletRequest.class);
            SessionDataCacheEntry mockSessionDataCacheEntry = mock(SessionDataCacheEntry.class);
            AuthenticatedUser impersonatedUser = mock(AuthenticatedUser.class);
            AuthenticatedUser impersonator = mock(AuthenticatedUser.class);
            ImpersonationRequestDTO impersonationRequestDTO = mock(ImpersonationRequestDTO.class);
            when(impersonationRequestDTO.getClientId()).thenReturn(dummyClientId);

            // Mark whether the request is a valid token initiation.
            Map<String, String[]> requestParameterMap = new HashMap<>();
            requestParameterMap.put(REQUESTED_SUBJECT, new String[]{impersonatedUserIdInReq});
            requestParameterMap.put(FrameworkConstants.SESSION_DATA_KEY, new String[]{"dummyKey"});

            // Mock request parameter map.
            when(oAuthMessage.getRequest()).thenReturn(mockRequest);
            when(mockRequest.getParameterMap()).thenReturn(requestParameterMap);

            // when OAuth2Parameters.getResponseType() return grant type.
            when(oAuth2Parameters.getResponseType()).thenReturn(responseType);
            when(oAuth2Parameters.getLoginTenantDomain()).thenReturn("carbon.super");
            when(oAuth2Parameters.getTenantDomain()).thenReturn("carbon.super");
            when(oAuth2Parameters.getClientId()).thenReturn(dummyClientId);
            when(oAuth2Parameters.getScopes()).thenReturn(new HashSet<String>(Collections.singletonList(
                    IMPERSONATION_SCOPE_NAME)));

            // IdentityTenantUtil.getTenantId
            identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenReturn(1234);

            // Pretend session exist -> SSO case.
            when(authCookie.getValue()).thenReturn("dummyValue");
            frameworkUtils.when(() -> FrameworkUtils.getAuthCookie(any())).thenReturn(authCookie);
            frameworkUtils.when(() -> FrameworkUtils.getSessionContextFromCache(anyString(), anyString()))
                    .thenReturn(sessionContext);

            // Set impersonating user.
            when(impersonator.getUserName()).thenReturn("impersonatingActor");
            when(impersonator.getUserId()).thenReturn("impersonatingActorId");
            when(impersonator.getTenantDomain()).thenReturn("carbon.super");
            when(impersonator.getUserStoreDomain()).thenReturn("PRIMARY");
            when(impersonator.getAuthenticatedSubjectIdentifier()).thenReturn("impersonatingActor");
            // Set impersonating user.as AuthenticationResult subject.
            authenticationResult.setSubject(impersonator);

            // Mock Session data Cache Entry.
            when(mockSessionDataCacheEntry.getLoggedInUser()).thenReturn(impersonator);

            // Mock OAuthMessage.
            when(oAuthMessage.getSessionDataCacheEntry()).thenReturn(mockSessionDataCacheEntry);
            when(mockSessionDataCacheEntry.getParamMap()).thenReturn(requestParameterMap);

            // Set impersonatedUser in the sessionContext.
            when(sessionContext.getImpersonatedUser()).thenReturn(existingImpersonatedUserId);

            // Mock OAuthAppDO.
            OAuthAppDO oAuthAppDO = mock(OAuthAppDO.class);
            AppInfoCache mockAppInfoCache = mock(AppInfoCache.class);
            appInfoCache.when(AppInfoCache::getInstance).thenReturn(mockAppInfoCache);
            when(mockAppInfoCache.getValueFromCache(anyString())).thenReturn(oAuthAppDO);

            // Mock impersonation validators.
            ImpersonationContext resultContext = mock(ImpersonationContext.class);
            when(resultContext.getImpersonationRequestDTO()).thenReturn(impersonationRequestDTO);
            when(resultContext.isValidated()).thenReturn(validImpersonation);

            // Mock ImpersonationMgtService.
            ImpersonationMgtService impersonationMgtService = mock(ImpersonationMgtServiceImpl.class);
            OAuth2ServiceComponentHolder.getInstance().setImpersonationMgtService(impersonationMgtService);
            when(impersonationMgtService.validateImpersonationRequest(any(ImpersonationRequestDTO.class)))
                    .thenReturn(resultContext);

            try (MockedStatic<OAuth2Util> mockedOAuth2Util = mockStatic(OAuth2Util.class);) {
                // Invoke impersonation validation.
                when(impersonatedUser.getUserId()).thenReturn(impersonatedUserIdInReq);
                mockedOAuth2Util.when(() -> OAuth2Util.getImpersonatingUser(
                        impersonatedUserIdInReq, impersonator.getTenantDomain(),
                        dummyClientId)).thenReturn(impersonatedUser);

                // Invoke handleSessionImpersonation method.
                Class<?> clazz = OAuth2AuthzEndpoint.class;
                Object authzEndpointObj = clazz.newInstance();
                Method handleSessionImpersonation = authzEndpointObj.getClass().
                        getDeclaredMethod("handleSessionImpersonation", OAuthMessage.class, String.class,
                                OAuth2Parameters.class, AuthenticationResult.class);
                handleSessionImpersonation.setAccessible(true);

                if (rejectImpersonation) {
                    assertThrows(Exception.class, () -> {
                        handleSessionImpersonation.invoke(authzEndpointObj,
                                oAuthMessage, "", oAuth2Parameters, authenticationResult);
                    });
                } else {
                    if (ssoImpersonation) {
                        handleSessionImpersonation.invoke(authzEndpointObj,
                                oAuthMessage, "", oAuth2Parameters, authenticationResult);
                        assertEquals(Objects.equals(authenticationResult.getSubject().getUserId(),
                                impersonatedUser.getUserId()), validImpersonation);
                    }
                }
            }
        }
    }
}
