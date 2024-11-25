package org.wso2.carbon.identity.oauth.cache;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
import org.wso2.carbon.identity.oauth2.dao.AuthorizationCodeDAO;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;

import java.text.ParseException;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AuthorizationGrantCacheTest {

    @Mock
    private AccessTokenDAO accessTokenDAO;

    private AuthorizationGrantCache cache;

    @Mock
    private OAuthTokenPersistenceFactory mockedOAuthTokenPersistenceFactory;

    @Mock
    private AuthorizationCodeDAO authorizationCodeDAO;

    @Mock
    private SessionDataStore sessionDataStore;

    private static final String AUTHORIZATION_GRANT_CACHE_NAME = "AuthorizationGrantCache";

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        cache = AuthorizationGrantCache.getInstance();
    }

    @Test(dataProvider = "replaceFromTokenIdDataProvider")
    public void testReplaceFromTokenId(String accessToken, String jwtId, String tokenId, boolean isJwtToken,
                                       boolean isInvalidJWTToken, boolean isFailedTokenRetrieval) throws Exception {

        try (MockedStatic<OAuthTokenPersistenceFactory> mockedFactory = mockStatic(OAuthTokenPersistenceFactory.class);
             MockedStatic<JWTParser> mockedJwtParser = mockStatic(JWTParser.class);
             MockedStatic<SessionDataStore> mockedSessionDataStore = mockStatic(SessionDataStore.class);
             MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class)) {

            mockedFactory.when(OAuthTokenPersistenceFactory::getInstance).thenReturn(
                    mockedOAuthTokenPersistenceFactory);

            when(mockedOAuthTokenPersistenceFactory.getAccessTokenDAO()).thenReturn(accessTokenDAO);

            if (isJwtToken) {
                JWT jwtMock = mock(JWT.class);
                JWTClaimsSet claimsSetMock = mock(JWTClaimsSet.class);

                if (isInvalidJWTToken) {
                    when(JWTParser.parse(accessToken)).thenThrow(new ParseException("Invalid JWT", 0));
                } else {
                    mockedJwtParser.when(() -> JWTParser.parse(accessToken)).thenReturn(jwtMock);
                    when(jwtMock.getJWTClaimsSet()).thenReturn(claimsSetMock);
                    when(claimsSetMock.getJWTID()).thenReturn(jwtId);
                }
            }

            if (isFailedTokenRetrieval) {
                when(accessTokenDAO.getTokenIdByAccessToken(jwtId)).thenThrow(
                        new IdentityOAuth2Exception("Failed to retrieve token id by token from store"));
            } else {
                when(accessTokenDAO.getTokenIdByAccessToken(jwtId != null ? jwtId : accessToken)).thenReturn(tokenId);
            }

            // Mock SessionDataStore static instance and return a mock session data store.
            mockedSessionDataStore.when(SessionDataStore::getInstance).thenReturn(sessionDataStore);

            AuthorizationGrantCacheEntry mockCacheEntry = new AuthorizationGrantCacheEntry();
            mockCacheEntry.setTokenId(tokenId);

            when(sessionDataStore.getSessionData(tokenId, AUTHORIZATION_GRANT_CACHE_NAME)).thenReturn(mockCacheEntry);

            AuthorizationGrantCacheKey key = new AuthorizationGrantCacheKey(accessToken);
            AuthorizationGrantCacheEntry result = cache.getValueFromCacheByToken(key);

            // Verify the token ID returned from the DAO is as expected.
            assertEquals(tokenId, result.getTokenId());

            // Verify that the JWT token was parsed and the correct claim was retrieved if it was a JWT.
            if (isJwtToken && !isInvalidJWTToken) {
                verify(accessTokenDAO).getTokenIdByAccessToken(jwtId);
            } else {
                verify(accessTokenDAO).getTokenIdByAccessToken(accessToken);
            }
        }
    }

    @DataProvider(name = "replaceFromTokenIdDataProvider")
    public Object[][] getReplaceFromTokenIdData() {

        return new Object[][]{
                {"jwt.Access.Token", "jwtId", "jwtTokenId", true, false, false},
                {"nonJWTAccessToken", null, "nonJWTTokenId", false, false, false},
                {"invalid.JWT.Token", null, "invalid.JWT.Token", true, true, false},
                {"fail.Store.TokenId", "jwtId", "jwtId", true, false, true}
        };
    }

    @Test
    public void testGetValueFromCacheByCode() throws IdentityOAuth2Exception {

        String authCode = "authCode";
        String codeId = "codeId";
        AuthorizationGrantCacheKey key = new AuthorizationGrantCacheKey(authCode);
        AuthorizationGrantCacheEntry expectedEntry = new AuthorizationGrantCacheEntry();
        expectedEntry.setCodeId(codeId);

        try (MockedStatic<OAuthTokenPersistenceFactory> mockedFactory = mockStatic(OAuthTokenPersistenceFactory.class);
             MockedStatic<SessionDataStore> mockedSessionDataStore = mockStatic(SessionDataStore.class);
             MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class)) {

            mockedSessionDataStore.when(SessionDataStore::getInstance).thenReturn(sessionDataStore);
            when(sessionDataStore.getSessionData(codeId, "AuthorizationGrantCache")).thenReturn(expectedEntry);

            mockedFactory.when(OAuthTokenPersistenceFactory::getInstance).
                    thenReturn(mockedOAuthTokenPersistenceFactory);
            when(mockedOAuthTokenPersistenceFactory.getAuthorizationCodeDAO()).thenReturn(authorizationCodeDAO);
            when(authorizationCodeDAO.getCodeIdByAuthorizationCode(authCode)).thenReturn(codeId);

            AuthorizationGrantCacheEntry result = cache.getValueFromCacheByCode(key);

            assertEquals(expectedEntry, result);
        }
    }
}
