/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com)
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

package org.wso2.carbon.identity.oauth2.token.bindings.handlers;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.util.AccessTokenEventUtil;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the session mapping based revocation carried out by {@link TokenBindingExpiryEventHandler}
 * on a front channel logout, for applications that have no access token binding configured.
 */
@WithCarbonHome
public class TokenBindingExpiryEventHandlerTest {

    private static final String CONSUMER_KEY = "test_consumer_key";
    private static final String SESSION_ID = "test_session_context_identifier";
    private static final String TOKEN_ID = "test_token_id";
    private static final String ACCESS_TOKEN = "test_access_token";

    private TokenBindingExpiryEventHandler handler;
    private AutoCloseable closeable;

    @Mock
    private OAuthTokenPersistenceFactory mockTokenPersistenceFactory;
    @Mock
    private AccessTokenDAO mockAccessTokenDAO;
    @Mock
    private HttpServletRequest mockRequest;
    @Mock
    private AuthenticationContext mockContext;
    @Mock
    private OAuthAppDO mockOAuthAppDO;
    @Mock
    private AccessTokenDO mockAccessTokenDO;

    private MockedStatic<OAuth2Util> oAuth2Util;
    private MockedStatic<OAuthTokenPersistenceFactory> tokenPersistenceFactory;
    private MockedStatic<OAuthUtil> oAuthUtil;
    private MockedStatic<AccessTokenEventUtil> accessTokenEventUtil;

    @BeforeMethod
    public void setUp() throws Exception {

        closeable = MockitoAnnotations.openMocks(this);
        handler = new TokenBindingExpiryEventHandler();

        oAuth2Util = mockStatic(OAuth2Util.class);
        tokenPersistenceFactory = mockStatic(OAuthTokenPersistenceFactory.class);
        oAuthUtil = mockStatic(OAuthUtil.class);
        accessTokenEventUtil = mockStatic(AccessTokenEventUtil.class);

        tokenPersistenceFactory.when(OAuthTokenPersistenceFactory::getInstance)
                .thenReturn(mockTokenPersistenceFactory);
        lenient().when(mockTokenPersistenceFactory.getAccessTokenDAO()).thenReturn(mockAccessTokenDAO);
        lenient().when(mockTokenPersistenceFactory.getAccessTokenDAOImpl(anyString())).thenReturn(mockAccessTokenDAO);

        // A front channel OIDC logout of an application that has no token binding type.
        lenient().when(mockRequest.getParameter(FrameworkConstants.RequestParams.TYPE))
                .thenReturn(FrameworkConstants.RequestType.CLAIM_TYPE_OIDC);
        lenient().when(mockContext.getRelyingParty()).thenReturn(CONSUMER_KEY);
        lenient().when(mockContext.getLastAuthenticatedUser()).thenReturn(new AuthenticatedUser());
        lenient().when(mockOAuthAppDO.getTokenBindingType()).thenReturn(null);
        oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(CONSUMER_KEY)).thenReturn(mockOAuthAppDO);

        // One token mapped to the terminated session.
        lenient().when(mockAccessTokenDAO.getTokenIdBySessionIdentifier(SESSION_ID))
                .thenReturn(Collections.singleton(TOKEN_ID));
        lenient().when(mockAccessTokenDAO.getAccessTokenByTokenId(TOKEN_ID)).thenReturn(ACCESS_TOKEN);
        lenient().when(mockAccessTokenDO.getConsumerKey()).thenReturn(CONSUMER_KEY);
        lenient().when(mockAccessTokenDO.getAccessToken()).thenReturn(ACCESS_TOKEN);
        lenient().when(mockAccessTokenDO.getAuthzUser()).thenReturn(new AuthenticatedUser());
        lenient().when(mockAccessTokenDO.getTokenBinding()).thenReturn(null);
        oAuth2Util.when(() -> OAuth2Util.getAccessTokenDOFromTokenIdentifier(ACCESS_TOKEN, false))
                .thenReturn(mockAccessTokenDO);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        closeMockSafely(oAuth2Util);
        closeMockSafely(tokenPersistenceFactory);
        closeMockSafely(oAuthUtil);
        closeMockSafely(accessTokenEventUtil);
        if (closeable != null) {
            closeable.close();
        }
    }

    private void closeMockSafely(MockedStatic<?> mock) {

        if (mock != null) {
            try {
                mock.close();
            } catch (Exception e) {
                // Ignore if already closed.
            }
        }
    }

    private Event sessionTerminateEvent() {

        Map<String, Object> paramMap = new HashMap<>();
        paramMap.put(FrameworkConstants.AnalyticsAttributes.SESSION_ID, SESSION_ID);
        paramMap.put(FrameworkConstants.AnalyticsAttributes.USER, new AuthenticatedUser());

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.REQUEST, mockRequest);
        eventProperties.put(IdentityEventConstants.EventProperty.CONTEXT, mockContext);
        eventProperties.put(IdentityEventConstants.EventProperty.PARAMS, paramMap);

        return new Event(IdentityEventConstants.EventName.SESSION_TERMINATE.name(), eventProperties);
    }

    /**
     * The defect this fixes: an unbound token has no binding reference pointing back to the session, so it has to
     * be found through the token to session mapping instead.
     */
    @Test
    public void testUnboundTokenIsRevokedOnFrontChannelLogoutWhenAppOptedIn() throws Exception {

        when(mockOAuthAppDO.isTokenRevocationWithIDPSessionTerminationEnabled()).thenReturn(true);

        handler.handleEvent(sessionTerminateEvent());

        verify(mockAccessTokenDAO, times(1)).revokeAccessTokens(any(String[].class), anyBoolean());
    }

    /**
     * User initiated logout honours the per application opt-in, so that revocation does not silently break
     * use cases such as offline_access.
     */
    @Test
    public void testUnboundTokenIsNotRevokedOnFrontChannelLogoutWhenAppNotOptedIn() throws Exception {

        when(mockOAuthAppDO.isTokenRevocationWithIDPSessionTerminationEnabled()).thenReturn(false);

        handler.handleEvent(sessionTerminateEvent());

        verify(mockAccessTokenDAO, never()).revokeAccessTokens(any(String[].class), anyBoolean());
    }

    /**
     * A failed application lookup must not revoke, since the opt-in cannot be established.
     */
    @Test
    public void testTokenIsNotRevokedWhenApplicationLookupFails() throws Exception {

        /*
         The first lookup is the one handleEvent does to read the binding type; it has to succeed so that the
         flow actually reaches the session mapping. The second is the one made while resolving the opt-in.
        */
        oAuth2Util.when(() -> OAuth2Util.getAppInformationByClientId(CONSUMER_KEY))
                .thenReturn(mockOAuthAppDO)
                .thenThrow(new InvalidOAuthClientException("No application found."));

        handler.handleEvent(sessionTerminateEvent());

        verify(mockAccessTokenDAO, times(1)).getTokenIdBySessionIdentifier(SESSION_ID);
        verify(mockAccessTokenDAO, never()).revokeAccessTokens(any(String[].class), anyBoolean());
    }

    /**
     * A mapping row whose token no longer resolves must be skipped without abandoning the remaining tokens of
     * the session.
     */
    @Test
    public void testUnresolvableTokenDoesNotAbortTheSessionSweep() throws Exception {

        String staleTokenId = "stale_token_id";
        when(mockOAuthAppDO.isTokenRevocationWithIDPSessionTerminationEnabled()).thenReturn(true);
        // TestNG iterates the set in insertion order, so the stale id is visited first.
        when(mockAccessTokenDAO.getTokenIdBySessionIdentifier(SESSION_ID))
                .thenReturn(new java.util.LinkedHashSet<>(java.util.Arrays.asList(staleTokenId, TOKEN_ID)));
        when(mockAccessTokenDAO.getAccessTokenByTokenId(staleTokenId)).thenReturn(null);

        handler.handleEvent(sessionTerminateEvent());

        verify(mockAccessTokenDAO, times(1)).revokeAccessTokens(any(String[].class), anyBoolean());
    }

    /**
     * A request-less session termination is a forced one: password change, account lock, user deletion, admin
     * session termination or federated backchannel logout. Those must revoke regardless of the per application
     * opt-in, otherwise a token would survive the very flows meant to kill it.
     */
    @Test
    public void testForcedSessionTerminationRevokesEvenWhenAppNotOptedIn() throws Exception {

        lenient().when(mockOAuthAppDO.isTokenRevocationWithIDPSessionTerminationEnabled()).thenReturn(false);

        Map<String, Object> paramMap = new HashMap<>();
        paramMap.put(FrameworkConstants.AnalyticsAttributes.SESSION_ID, SESSION_ID);
        paramMap.put(FrameworkConstants.AnalyticsAttributes.USER, new AuthenticatedUser());

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.PARAMS, paramMap);
        eventProperties.put(IdentityEventConstants.EventProperty.SESSION_CONTEXT, new SessionContext());

        handler.handleEvent(new Event(IdentityEventConstants.EventName.SESSION_TERMINATE.name(), eventProperties));

        verify(mockAccessTokenDAO, times(1)).revokeAccessTokens(any(String[].class), anyBoolean());
    }

    /**
     * An event that carries no session identifier must be a no-op rather than a failure.
     */
    @Test
    public void testEventWithoutSessionIdentifierIsIgnored() throws Exception {

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.REQUEST, mockRequest);
        eventProperties.put(IdentityEventConstants.EventProperty.CONTEXT, mockContext);
        eventProperties.put(IdentityEventConstants.EventProperty.PARAMS, null);

        handler.handleEvent(new Event(IdentityEventConstants.EventName.SESSION_TERMINATE.name(), eventProperties));

        verify(mockAccessTokenDAO, never()).revokeAccessTokens(any(String[].class), anyBoolean());
        verify(mockAccessTokenDAO, never()).getTokenIdBySessionIdentifier(eq(SESSION_ID));
    }
}
