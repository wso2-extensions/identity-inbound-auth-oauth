package org.wso2.carbon.identity.oauth2.token.handlers.claims;

import org.mockito.MockedStatic;
import org.testng.annotations.Test;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.action.execution.api.model.ActionType;
import org.wso2.carbon.identity.action.execution.api.service.ActionExecutorService;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.RefreshGrantHandler;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashSet;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.REFRESH_TOKEN;
import static org.wso2.carbon.identity.oauth2.token.handlers.grant.RefreshGrantHandler.PREV_ACCESS_TOKEN;

/**
 * This test class checks whether access token flow gets values of acr and auth_time claims
 * in the case of AuthorizationGrantCache has successfully stored those values against
 * the access token id.
 */
@WithCarbonHome
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB",
        files = {"dbScripts/identity.sql", "dbScripts/insert_application_and_token_for_refresh_token_expiry.sql",
                "dbScripts/insert_consumer_app.sql", "dbScripts/insert_local_idp.sql"})
@WithRealmService(injectToSingletons = {OAuthComponentServiceHolder.class})

public class AccessTokenStepUpAuthClaimsSetTest {

    private static final String TOKEN_ID = "test-token-id";

    @Test
    public void testStepUpClaimsAtRefreshGrant() throws Exception {

        CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME = false;
        final String testAcr = "test_acr";
        final long testAuthTime = 1686239200L;
        final long testMaxAge = 3000L;
        LinkedHashSet<String> testAcrValue = new LinkedHashSet<>();
        testAcrValue.add("test_acr_value_1");
        testAcrValue.add("test_acr_value_2");

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
        validationBean.setTokenId(TOKEN_ID);

        tokReqMsgCtx.addProperty(PREV_ACCESS_TOKEN, validationBean);

        ActionExecutorService actionExecutorService = mock(ActionExecutorService.class);
        when(actionExecutorService.isExecutionEnabled(ActionType.PRE_ISSUE_ACCESS_TOKEN)).thenReturn(false);
        OAuthComponentServiceHolder.getInstance().setActionExecutorService(actionExecutorService);

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(TOKEN_ID);
        AuthorizationGrantCacheEntry cacheEntry = spy(new AuthorizationGrantCacheEntry());
        cacheEntry.setAcrValue(testAcrValue);
        cacheEntry.setSelectedAcrValue(testAcr);
        cacheEntry.setMaxAge(testMaxAge);
        cacheEntry.setAuthTime(testAuthTime);
        try (MockedStatic<AuthorizationGrantCache> mocked = mockStatic(AuthorizationGrantCache.class)) {
            AuthorizationGrantCache mockCache = mock(AuthorizationGrantCache.class);
            mocked.when(AuthorizationGrantCache::getInstance).thenReturn(mockCache);
            when(mockCache.getValueFromCacheByTokenId(cacheKey, TOKEN_ID)).thenReturn(cacheEntry);

            RefreshGrantHandler refreshGrantHandler = spy(new RefreshGrantHandler());
            refreshGrantHandler.init();
            OAuth2AccessTokenRespDTO refreshTokenDTO = refreshGrantHandler.issue(tokReqMsgCtx);
            assertEquals(tokReqMsgCtx.getSelectedAcr(), testAcr);
            assertEquals(tokReqMsgCtx.getAuthTime(), testAuthTime);
        }
    }
}
