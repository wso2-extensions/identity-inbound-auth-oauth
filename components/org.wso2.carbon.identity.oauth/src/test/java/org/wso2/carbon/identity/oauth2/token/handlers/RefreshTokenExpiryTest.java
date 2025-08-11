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

package org.wso2.carbon.identity.oauth2.token.handlers;

import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.service.ActionExecutorService;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.RefreshGrantHandler;

import java.sql.Timestamp;
import java.time.Instant;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.AUTHORIZATION_CODE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.REFRESH_TOKEN;
import static org.wso2.carbon.identity.oauth2.token.handlers.grant.RefreshGrantHandler.PREV_ACCESS_TOKEN;

/**
 * This test class covers the refresh token expiry time behavior in the OAuthTokenReqMessageContext.
 */
@WithCarbonHome
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB",
        files = {"dbScripts/identity.sql", "dbScripts/insert_application_and_token_for_refresh_token_expiry.sql",
                "dbScripts/insert_consumer_app.sql", "dbScripts/insert_local_idp.sql"})
@WithRealmService(injectToSingletons = {OAuthComponentServiceHolder.class})
public class RefreshTokenExpiryTest {

    // Refer insert_application_and_token_for_refresh_token_expiry.sql for application info.
    long refreshTokenExpiryInSecondsInDB = 72600;

    @Test
    public void testRefreshTokenExpiryAtRefreshGrant() throws Exception {

        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = false;

        OAuth2AccessTokenReqDTO tokenReq = mock(OAuth2AccessTokenReqDTO.class);
        when(tokenReq.getClientId()).thenReturn("ca19a540f544777860e44e75f605d927");
        when(tokenReq.getGrantType()).thenReturn(REFRESH_TOKEN);

        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        when(authenticatedUser.getTenantDomain()).thenReturn("carbon.super");
        when(authenticatedUser.getUserId()).thenReturn("user-id");

        OAuthTokenReqMessageContext tokReqMsgCtx = spy(new OAuthTokenReqMessageContext(tokenReq));
        String[] scopeArray = new String[]{"openid", "profile"};
        tokReqMsgCtx.setScope(scopeArray);
        tokReqMsgCtx.setAuthorizedUser(authenticatedUser);

        RefreshTokenValidationDataDO validationBean = new RefreshTokenValidationDataDO();
        validationBean.setAccessTokenValidityInMillis(3600000L);
        validationBean.setIssuedTime(Timestamp.from(Instant.now()));
        validationBean.setAuthorizedUser(authenticatedUser);
        validationBean.setGrantType(REFRESH_TOKEN);

        tokReqMsgCtx.addProperty(PREV_ACCESS_TOKEN, validationBean);

        ActionExecutorService actionExecutorService = mock(ActionExecutorService.class);
        when(actionExecutorService.isExecutionEnabled(ActionType.PRE_ISSUE_ACCESS_TOKEN)).thenReturn(false);
        OAuthComponentServiceHolder.getInstance().setActionExecutorService(actionExecutorService);

        RefreshGrantHandler refreshGrantHandler = spy(new RefreshGrantHandler());
        refreshGrantHandler.init();
        OAuth2AccessTokenRespDTO refreshTokenDTO = refreshGrantHandler.issue(tokReqMsgCtx);
        assertNotNull(refreshTokenDTO);
        assertEquals(tokReqMsgCtx.getRefreshTokenvalidityPeriod(), refreshTokenExpiryInSecondsInDB * 1000);
    }

    @Test
    public void testRefreshTokenExpiryAtAuthorizationCodeGrant() throws Exception {

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain("carbon.super");
        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = false;

        OAuth2AccessTokenReqDTO tokenReq = mock(OAuth2AccessTokenReqDTO.class);
        when(tokenReq.getClientId()).thenReturn("ca19a540f544777860e44e75f605d927");
        when(tokenReq.getGrantType()).thenReturn(AUTHORIZATION_CODE);

        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        when(authenticatedUser.getTenantDomain()).thenReturn("carbon.super");
        when(authenticatedUser.getUserId()).thenReturn("user-abc");

        OAuthTokenReqMessageContext tokReqMsgCtx = spy(new OAuthTokenReqMessageContext(tokenReq));
        String[] scopeArray = new String[]{"openid", "profile"};
        tokReqMsgCtx.setScope(scopeArray);
        tokReqMsgCtx.setAuthorizedUser(authenticatedUser);

        ActionExecutorService actionExecutorService = mock(ActionExecutorService.class);
        when(actionExecutorService.isExecutionEnabled(ActionType.PRE_ISSUE_ACCESS_TOKEN)).thenReturn(false);
        OAuthComponentServiceHolder.getInstance().setActionExecutorService(actionExecutorService);

        MockAuthzGrantHandler authorizationCodeGrantHandler = spy(new MockAuthzGrantHandler());
        authorizationCodeGrantHandler.init();
        OAuth2AccessTokenRespDTO refreshTokenDTO = authorizationCodeGrantHandler.issue(tokReqMsgCtx);
        assertNotNull(refreshTokenDTO);
        assertEquals(tokReqMsgCtx.getRefreshTokenvalidityPeriod(), refreshTokenExpiryInSecondsInDB * 1000);
    }

    @Test
    public void testRefreshTokenExpiryAtRefreshGrantPreIssueAccessTokenActionEnabled() throws Exception {

        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = false;

        OAuth2AccessTokenReqDTO tokenReq = mock(OAuth2AccessTokenReqDTO.class);
        when(tokenReq.getClientId()).thenReturn("ca19a540f544777860e44e75f605d927");
        when(tokenReq.getGrantType()).thenReturn(REFRESH_TOKEN);

        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        when(authenticatedUser.getTenantDomain()).thenReturn("carbon.super");
        when(authenticatedUser.getUserId()).thenReturn("user-id");

        OAuthTokenReqMessageContext tokReqMsgCtx = spy(new OAuthTokenReqMessageContext(tokenReq));
        String[] scopeArray = new String[]{"openid", "profile"};
        tokReqMsgCtx.setScope(scopeArray);
        tokReqMsgCtx.setAuthorizedUser(authenticatedUser);

        RefreshTokenValidationDataDO validationBean = new RefreshTokenValidationDataDO();
        validationBean.setAccessTokenValidityInMillis(3600000L);
        validationBean.setIssuedTime(Timestamp.from(Instant.now()));
        validationBean.setAuthorizedUser(authenticatedUser);
        validationBean.setGrantType(REFRESH_TOKEN);

        tokReqMsgCtx.addProperty(PREV_ACCESS_TOKEN, validationBean);

        ActionExecutorService actionExecutorService = mock(ActionExecutorService.class);
        when(actionExecutorService.isExecutionEnabled(ActionType.PRE_ISSUE_ACCESS_TOKEN)).thenReturn(false);
        OAuthComponentServiceHolder.getInstance().setActionExecutorService(actionExecutorService);

        RefreshGrantHandler refreshGrantHandler = spy(new RefreshGrantHandler());
        refreshGrantHandler.init();
        OAuth2AccessTokenRespDTO refreshTokenDTO = refreshGrantHandler.issue(tokReqMsgCtx);
        assertNotNull(refreshTokenDTO);
        assertEquals(tokReqMsgCtx.getRefreshTokenvalidityPeriod(), refreshTokenExpiryInSecondsInDB * 1000);
    }

    private static class MockAuthzGrantHandler extends AbstractAuthorizationGrantHandler {

    }
}
