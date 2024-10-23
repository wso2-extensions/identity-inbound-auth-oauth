package org.wso2.carbon.identity.oauth.cache;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.wso2.carbon.identity.oauth2.dao.AccessTokenDAO;
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

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        cache = AuthorizationGrantCache.getInstance();

        // Mock OAuthTokenPersistenceFactory and AccessTokenDAO
        mockStatic(OAuthTokenPersistenceFactory.class);
        when(OAuthTokenPersistenceFactory.getInstance()).thenReturn(mockedOAuthTokenPersistenceFactory);

        // Mock the getAccessTokenDAO() method
        when(mockedOAuthTokenPersistenceFactory.getAccessTokenDAO()).thenReturn(accessTokenDAO);
    }

    @Test
    public void testReplaceFromTokenId_withJWTToken() throws Exception {
        // Mock JWT token parsing and claim retrieval
        JWT jwtMock = mock(JWT.class);
        JWTClaimsSet claimsSetMock = mock(JWTClaimsSet.class);

        when(JWTParser.parse("jwtAccessToken")).thenReturn(jwtMock);
        when(jwtMock.getJWTClaimsSet()).thenReturn(claimsSetMock);
        when(claimsSetMock.getJWTID()).thenReturn("jwtId123");

        // Mock DAO to return tokenId for the JWT ID
        when(accessTokenDAO.getTokenIdByAccessToken("jwtId123")).thenReturn("tokenId123");

        // Prepare cache key
        AuthorizationGrantCacheKey key = new AuthorizationGrantCacheKey("jwtAccessToken");

        // Call the public method which invokes replaceFromTokenId indirectly
        AuthorizationGrantCacheEntry result = cache.getValueFromCacheByToken(key);

        // Verify the token ID returned from the DAO is as expected
        assertEquals("tokenId123", result.getTokenId());

        // Verify that the JWT token was parsed and the correct claim was retrieved
        verify(claimsSetMock).getJWTID();
        verify(accessTokenDAO).getTokenIdByAccessToken("jwtId123");
    }

    @Test
    public void testReplaceFromTokenId_withNonJWTToken() throws Exception {
        // Mock DAO to return tokenId for the non-JWT access token
        when(accessTokenDAO.getTokenIdByAccessToken("nonJWTAccessToken")).thenReturn("tokenId456");

        // Prepare cache key with a non-JWT access token
        AuthorizationGrantCacheKey key = new AuthorizationGrantCacheKey("nonJWTAccessToken");

        // Call the public method which invokes replaceFromTokenId indirectly
        AuthorizationGrantCacheEntry result = cache.getValueFromCacheByToken(key);

        // Verify the token ID returned from the DAO is as expected
        assertEquals("tokenId456", result.getTokenId());

        // Verify the DAO was called with the access token directly (since it's not JWT)
        verify(accessTokenDAO).getTokenIdByAccessToken("nonJWTAccessToken");
    }

    @Test
    public void testReplaceFromTokenId_withJWTParseException() throws Exception {
        // Simulate JWT parsing failure
        when(JWTParser.parse("invalidJWTToken")).thenThrow(new ParseException("Invalid JWT", 0));

        // Mock DAO to return tokenId for the token (even though it's invalid JWT)
        when(accessTokenDAO.getTokenIdByAccessToken("invalidJWTToken")).thenReturn("tokenId789");

        // Prepare cache key with an invalid JWT access token
        AuthorizationGrantCacheKey key = new AuthorizationGrantCacheKey("invalidJWTToken");

        // Call the public method which invokes replaceFromTokenId indirectly
        AuthorizationGrantCacheEntry result = cache.getValueFromCacheByToken(key);

        // Verify the token ID returned from the DAO is as expected
        assertEquals("tokenId789", result.getTokenId());

        // Verify that the DAO was called even though JWT parsing failed
        verify(accessTokenDAO).getTokenIdByAccessToken("invalidJWTToken");
    }
}
