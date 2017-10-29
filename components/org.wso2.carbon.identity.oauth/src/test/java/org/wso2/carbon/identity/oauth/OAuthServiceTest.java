/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth;

import com.google.gdata.client.authn.oauth.GoogleOAuthParameters;
import com.google.gdata.client.authn.oauth.OAuthException;
import com.google.gdata.client.authn.oauth.OAuthHmacSha1Signer;
import com.google.gdata.client.authn.oauth.OAuthUtil;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.context.ServiceContext;
import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.common.AuthenticationException;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dao.OAuthConsumerDAO;
import org.wso2.carbon.identity.oauth.dto.OAuthConsumerDTO;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.net.URLEncoder;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for OAuthService.
 */
@PowerMockIgnore({"javax.net.*", "javax.security.*", "javax.crypto.*"})
@PrepareForTest({OAuthConsumerDAO.class, OAuthService.class, MessageContext.class, MultitenantUtils.class,
        IdentityTenantUtil.class, OAuthAppDAO.class})
public class OAuthServiceTest extends PowerMockIdentityBaseTest {

    private static final Long LATEST_TIMESTAMP = new Timestamp(System.currentTimeMillis()).getTime();
    private static final Long GREATER_THAN_LATEST_TIMESTAMP = LATEST_TIMESTAMP + 10000;
    private static final String OAUTH_LATEST_TIMESTAMP = "OAUTH_LATEST_TIMESTAMP";
    private static final String OAUTH_NONCE_STORE = "OAUTH_NONCE_STORE";

    @Mock
    private OAuthConsumerDAO oAuthConsumerDAO;

    @Mock
    private ServiceContext serviceContext;

    @Mock
    private MessageContext messageContext;

    @Mock
    private UserRealm userRealm;

    @Mock
    private UserStoreManager userStoreManager;

    @Mock
    private OAuthAppDAO oAuthAppDAO;

    @DataProvider(name = "testIsOAuthConsumerValid")
    public Object[][] isOAuthConsumerValidFlows() {
        return new Object[][]{{true, true}, {true, false}, {false, true}, {false, false}};
    }

    @Test(dataProvider = "testIsOAuthConsumerValid")
    public void testIsOAuthConsumerValid(boolean shouldURLEncodeSignature,
                                         boolean shouldNonceStoreExist) throws Exception {

        String consumerSecret = "consumer-secret";
        // Create input request parameters.
        OAuthConsumerDTO oAuthConsumer = new OAuthConsumerDTO();
        oAuthConsumer.setOauthConsumerKey("consumer-key");
        oAuthConsumer.setOauthNonce("oauth-nonce");
        oAuthConsumer.setOauthTimeStamp(GREATER_THAN_LATEST_TIMESTAMP.toString());
        oAuthConsumer.setOauthSignatureMethod("HmacSHA1");
        oAuthConsumer.setBaseString("http://is.com:8080/playground.com");
        oAuthConsumer.setHttpMethod("HTTP-POST");
        // Create consumer signature.
        String signature = getConsumerSignature(oAuthConsumer, consumerSecret);
        // Set the created signature to the oAuthConsumer.
        oAuthConsumer.setOauthSignature(shouldURLEncodeSignature ? URLEncoder.encode(signature) : signature);

        prepareForValidateTimestampAndNonce(consumerSecret, shouldNonceStoreExist);
        OAuthService oAuthService = new OAuthService();
        assertTrue(oAuthService.isOAuthConsumerValid(oAuthConsumer), "Should be a valid consumer with the " +
                "valid signature.");
    }

    @DataProvider(name = "consumerSecretValidSignature")
    public Object[][] consumerSecretValidSignature() {
        return new Object[][]{{"consumer-secret", false}, {null, true}};
    }

    @Test(dataProvider = "consumerSecretValidSignature", expectedExceptions = IdentityException.class)
    public void testIsOAuthConsumerValidException(String consumerSecret, boolean isValidSignature) throws Exception {

        OAuthConsumerDTO oAuthConsumer = new OAuthConsumerDTO();
        oAuthConsumer.setOauthConsumerKey("consumer-key");
        String signature;
        if (isValidSignature) {
            oAuthConsumer.setOauthNonce("oauth-nonce");
            oAuthConsumer.setOauthTimeStamp(GREATER_THAN_LATEST_TIMESTAMP.toString());
            oAuthConsumer.setOauthSignatureMethod("HmacSHA1");
            oAuthConsumer.setBaseString("http://is.com:8080/playground.com");
            oAuthConsumer.setHttpMethod("HTTP-POST");
            signature = getConsumerSignature(oAuthConsumer, consumerSecret);
        } else {
            signature = "an-invalid-signature";
        }
        oAuthConsumer.setOauthSignature(signature);

        whenNew(OAuthConsumerDAO.class).withAnyArguments().thenReturn(oAuthConsumerDAO);
        when(oAuthConsumerDAO.getOAuthConsumerSecret(anyString())).thenReturn(consumerSecret);

        OAuthService oAuthService = new OAuthService();
        oAuthService.isOAuthConsumerValid(oAuthConsumer);
    }

    @Test
    public void testGetOauthRequestToken() throws Exception {

        String consumerSecret = "consumer-secret";
        // Create input request parameters.
        Parameters requestParams = new Parameters();
        requestParams.setOauthConsumerKey("consumer-key");
        requestParams.setOauthNonce("oauth-nonce");
        requestParams.setOauthTimeStamp(GREATER_THAN_LATEST_TIMESTAMP.toString());
        requestParams.setOauthSignatureMethod("HmacSHA1");
        requestParams.setBaseString("http://is.com:8080/playground.com");
        requestParams.setHttpMethod("HTTP-POST");
        requestParams.setOauthCallback("http://is.com:8080/playground.com");
        requestParams.setScope("openid");
        // Create consumer signature.
        String signature = getConsumerSignature(requestParams, consumerSecret, null);
        // Set the created signature to the request parameters.
        requestParams.setOauthSignature(signature);

        prepareForValidateTimestampAndNonce(consumerSecret, false);
        OAuthService oAuthService = new OAuthService();
        Parameters responseParams = oAuthService.getOauthRequestToken(requestParams);
        assertEquals(responseParams.getOauthConsumerKey(), requestParams.getOauthConsumerKey(), "ConsumerKey should" +
                " be same as the given ConsumerKey.");
        assertTrue(StringUtils.isNotBlank(responseParams.getOauthToken()), "Should generate an non-blank OAuthToken.");
        assertTrue(StringUtils.isNotBlank(responseParams.getOauthTokenSecret()), "Should generate an non-blank " +
                "OAuthTokenSecret.");
    }

    @Test(dataProvider = "consumerSecretValidSignature", expectedExceptions = AuthenticationException.class)
    public void testGetOauthRequestTokenException(String consumerSecret, boolean isValidSignature) throws Exception {

        // Create input request parameters.
        Parameters requestParams = new Parameters();
        requestParams.setOauthConsumerKey("consumer-key");
        requestParams.setOauthNonce("oauth-nonce");
        requestParams.setOauthTimeStamp(GREATER_THAN_LATEST_TIMESTAMP.toString());
        requestParams.setOauthSignatureMethod("HmacSHA1");
        requestParams.setBaseString("http://is.com:8080/playground.com");
        requestParams.setHttpMethod("HTTP-POST");
        String signature;
        if (isValidSignature) {
            signature = getConsumerSignature(requestParams, consumerSecret, null);
        } else {
            signature = "an-invalid-signature";
        }
        requestParams.setOauthSignature(signature);

        prepareForValidateTimestampAndNonce(consumerSecret, false);
        OAuthService oAuthService = new OAuthService();
        oAuthService.getOauthRequestToken(requestParams);
    }

    @DataProvider(name = "testAuthorizeOauthRequestTokenException")
    public Object[][] authorizeOauthRequestTokenExceptionFlows() {
        return new Object[][]{{false, true}, {false, false}};
    }

    @Test(dataProvider = "testAuthorizeOauthRequestTokenException",
            expectedExceptions = {IdentityException.class, AuthenticationException.class})
    public void testAuthorizeOauthRequestTokenException(boolean shoulAuthenticate,
                                                        boolean shouldThrow) throws Exception {

        String authorizedSubject = "moana";
        // Create input request parameters.
        Parameters requestParams = new Parameters();
        requestParams.setAuthorizedbyUserName(authorizedSubject);
        requestParams.setAuthorizedbyUserPassword("password");
        requestParams.setOauthToken("oauth-token");

        prepareForauthorizeOauthRequestToken(authorizedSubject, shoulAuthenticate, shouldThrow);
        OAuthService oAuthService = new OAuthService();
        oAuthService.authorizeOauthRequestToken(requestParams);
    }

    @Test
    public void testAuthorizeOauthRequestToken() throws Exception {

        String authorizedSubject = "moana";
        // Create input request parameters.
        Parameters requestParams = new Parameters();
        requestParams.setAuthorizedbyUserName(authorizedSubject);
        requestParams.setAuthorizedbyUserPassword("password");
        requestParams.setOauthToken("oauth-token");

        prepareForauthorizeOauthRequestToken(authorizedSubject, true, false);
        whenNew(OAuthConsumerDAO.class).withAnyArguments().thenReturn(oAuthConsumerDAO);
        when(oAuthConsumerDAO.authorizeOAuthToken(anyString(), anyString(), anyString())).thenReturn(new Parameters());

        OAuthService oAuthService = new OAuthService();
        Parameters responseParams = oAuthService.authorizeOauthRequestToken(requestParams);
        assertEquals(responseParams.getOauthToken(), requestParams.getOauthToken(), "OauthToken in authorized params" +
                " should be same as the given oauthToken.");
        assertTrue(StringUtils.isNotBlank(responseParams.getOauthTokenVerifier()));
    }

    @Test
    public void testGetScopeAndAppName() throws Exception {

        // Create input request parameters.
        Parameters requestTokenParams = new Parameters();
        requestTokenParams.setOauthConsumerKey("consumer-key");
        requestTokenParams.setScope("openid");
        OAuthAppDO appInformation = new OAuthAppDO();
        appInformation.setApplicationName("application-name");

        whenNew(OAuthConsumerDAO.class).withAnyArguments().thenReturn(oAuthConsumerDAO);
        when(oAuthConsumerDAO.getRequestToken(anyString())).thenReturn(requestTokenParams);
        whenNew(OAuthAppDAO.class).withAnyArguments().thenReturn(oAuthAppDAO);
        when(oAuthAppDAO.getAppInformation(anyString())).thenReturn(appInformation);

        OAuthService oAuthService = new OAuthService();
        Parameters responseParams = oAuthService.getScopeAndAppName("oauth-token");
        assertEquals(responseParams.getScope(), requestTokenParams.getScope(), "Scope of the response parameters " +
                "should be same as the given Scope in requestTokenParas.");
        assertEquals(responseParams.getAppName(), appInformation.getApplicationName(), "AppName of the response " +
                "parameters should be same as the retrieved appInformation.");
    }

    @Test
    public void testValidateAuthenticationRequest() throws Exception {

        String consumerSecret = "consumer-secret";
        String tokenSecret = "token-secret";
        String authorizedSubject = "moana";
        // Create input request parameters.
        Parameters requestParams = new Parameters();
        requestParams.setOauthConsumerKey("consumer-key");
        requestParams.setOauthNonce("oauth-nonce");
        requestParams.setOauthTimeStamp(GREATER_THAN_LATEST_TIMESTAMP.toString());
        requestParams.setOauthSignatureMethod("HmacSHA1");
        requestParams.setBaseString("http://is.com:8080/playground.com");
        requestParams.setHttpMethod("HTTP-POST");
        requestParams.setScope("openid");
        requestParams.setOauthToken("oauth-token");
        requestParams.setOauthTokenVerifier("oauth-token-verifier");
        // Create consumer signature.
        String signature = getConsumerSignature(requestParams, consumerSecret, tokenSecret);
        // Set the created signature to the request parameters.
        requestParams.setOauthSignature(signature);

        prepareForValidateTimestampAndNonce(consumerSecret, false);
        whenNew(OAuthConsumerDAO.class).withAnyArguments().thenReturn(oAuthConsumerDAO);
        when(oAuthConsumerDAO.getOAuthConsumerSecret(anyString())).thenReturn(consumerSecret);
        when(oAuthConsumerDAO.getOAuthTokenSecret(anyString(), anyBoolean())).thenReturn(tokenSecret);
        when(oAuthConsumerDAO.validateAccessToken(anyString(), anyString(), anyString())).thenReturn(authorizedSubject);

        OAuthService oAuthService = new OAuthService();
        Parameters responseParams = oAuthService.validateAuthenticationRequest(requestParams);
        assertEquals(responseParams.getAuthorizedbyUserName(), authorizedSubject, "Value of AuthorizedByUserName in" +
                " response parameters should be same as the retrieved subject when validating the access token.");
        assertEquals(responseParams.getScope(), requestParams.getScope(), "Scope in the response parameters should " +
                "be same as the scope in the request parameters.");
    }

    @Test(dataProvider = "consumerSecretValidSignature",
            expectedExceptions = {AuthenticationException.class, AuthenticationException.class})
    public void testValidateAuthenticationRequestException(String consumerSecret,
                                                           boolean isValidSignature) throws Exception {

        // Create input request parameters.
        Parameters requestParams = new Parameters();
        requestParams.setOauthConsumerKey("consumer-key");
        requestParams.setOauthNonce("oauth-nonce");
        requestParams.setOauthTimeStamp(GREATER_THAN_LATEST_TIMESTAMP.toString());
        requestParams.setOauthSignatureMethod("HmacSHA1");
        requestParams.setBaseString("http://is.com:8080/playground.com");
        requestParams.setHttpMethod("HTTP-POST");
        String signature;
        if (isValidSignature) {
            signature = getConsumerSignature(requestParams, consumerSecret, null);
        } else {
            signature = "an-invalid-signature";
        }
        requestParams.setOauthSignature(signature);

        prepareForValidateTimestampAndNonce(consumerSecret, false);
        whenNew(OAuthConsumerDAO.class).withAnyArguments().thenReturn(oAuthConsumerDAO);
        when(oAuthConsumerDAO.getOAuthConsumerSecret(anyString())).thenReturn(consumerSecret);

        OAuthService oAuthService = new OAuthService();
        oAuthService.validateAuthenticationRequest(requestParams);
    }

    @Test
    public void testGetAccessToken() throws Exception {

        String consumerSecret = "consumer-secret";
        String tokenSecret = "token-secret";
        String authorizedSubject = "moana";
        String oauthTokenVerifier = "oauth-token-verifier";
        // Create input request parameters.
        Parameters requestParams = new Parameters();
        requestParams.setOauthConsumerKey("consumer-key");
        requestParams.setOauthNonce("oauth-nonce");
        requestParams.setOauthTimeStamp(GREATER_THAN_LATEST_TIMESTAMP.toString());
        requestParams.setOauthSignatureMethod("HmacSHA1");
        requestParams.setBaseString("http://is.com:8080/playground.com");
        requestParams.setHttpMethod("HTTP-POST");
        requestParams.setScope("openid");
        requestParams.setOauthToken("oauth-token");
        requestParams.setOauthTokenVerifier(oauthTokenVerifier);
        // Create consumer signature.
        String signature = getConsumerSignature(requestParams, consumerSecret, tokenSecret);
        // Set the created signature to the request parameters.
        requestParams.setOauthSignature(signature);

        // Prepare response for OAuthConsumerDAO.getRequestToken().
        Parameters requestToken = new Parameters();
        requestToken.setOauthTokenVerifier(oauthTokenVerifier);
        requestToken.setAuthorizedbyUserName(authorizedSubject);
        // Prepare for OAuthService.getAccessToken()
        prepareForValidateTimestampAndNonce(consumerSecret, false);
        whenNew(OAuthConsumerDAO.class).withAnyArguments().thenReturn(oAuthConsumerDAO);
        when(oAuthConsumerDAO.getOAuthConsumerSecret(anyString())).thenReturn(consumerSecret);
        when(oAuthConsumerDAO.getOAuthTokenSecret(anyString(), anyBoolean())).thenReturn(tokenSecret);
        when(oAuthConsumerDAO.getRequestToken(anyString())).thenReturn(requestToken);

        OAuthService oAuthService = new OAuthService();
        Parameters responseParams = oAuthService.getAccessToken(requestParams);
        assertNotNull(requestParams.getOauthTokenVerifier(), "In the reponseParams should have the tokenVerifier.");
        assertEquals(responseParams.getOauthTokenVerifier(), requestParams.getOauthTokenVerifier(), "In both response" +
                " and request parameters OAuthTokenVerifier should be the same.");
        assertNotNull(responseParams.getAuthorizedbyUserName(), "AuthorizedbyUserName should not be null in the " +
                "responseParams.");
        assertTrue(StringUtils.isNotBlank(responseParams.getOauthToken()), "OAuthToken should not be blank in the " +
                "responseParams.");
        assertTrue(StringUtils.isNotBlank(responseParams.getOauthTokenSecret()), "OAuthTokenSecret should not be " +
                "blank in the responseParams.");
    }

    @DataProvider(name = "testGetAccessTokenException")
    public Object[][] getAccessTokenExceptionFlows() {
        return new Object[][]{{"consumer-secret", false}, {null, false}, {"consumer-secret", true}};
    }

    @Test(dataProvider = "testGetAccessTokenException", expectedExceptions = AuthenticationException.class)
    public void testGetAccessTokenException(String consumerSecret, boolean isValidSignature) throws Exception {

        String tokenSecret = "token-secret";
        String oauthTokenVerifier = "oauth-token-verifier";
        // Create input request parameters.
        Parameters requestParams = new Parameters();
        requestParams.setOauthConsumerKey("consumer-key");
        requestParams.setOauthNonce("oauth-nonce");
        requestParams.setOauthTimeStamp(GREATER_THAN_LATEST_TIMESTAMP.toString());
        requestParams.setOauthSignatureMethod("HmacSHA1");
        requestParams.setBaseString("http://is.com:8080/playground.com");
        requestParams.setHttpMethod("HTTP-POST");
        requestParams.setScope("openid");
        requestParams.setOauthToken("oauth-token");
        requestParams.setOauthTokenVerifier(oauthTokenVerifier);
        String signature;
        if (isValidSignature) {
            signature = getConsumerSignature(requestParams, consumerSecret, tokenSecret);
        } else {
            signature = "invalid-signature";
        }
        requestParams.setOauthSignature(signature);

        // Prepare response for OAuthConsumerDAO.getRequestToken().
        Parameters requestToken = new Parameters();
        requestToken.setOauthTokenVerifier(oauthTokenVerifier);
        // Prepare for OAuthService.getAccessToken.
        prepareForValidateTimestampAndNonce(consumerSecret, false);
        whenNew(OAuthConsumerDAO.class).withAnyArguments().thenReturn(oAuthConsumerDAO);
        when(oAuthConsumerDAO.getOAuthConsumerSecret(anyString())).thenReturn(consumerSecret);
        when(oAuthConsumerDAO.getOAuthTokenSecret(anyString(), anyBoolean())).thenReturn(tokenSecret);
        when(oAuthConsumerDAO.getRequestToken(anyString())).thenReturn(requestToken);

        OAuthService oAuthService = new OAuthService();
        oAuthService.getAccessToken(requestParams);
    }

    private void prepareForValidateTimestampAndNonce(String consumerSecret,
                                                     boolean shouldNonceStoreExist) throws Exception {

        whenNew(OAuthConsumerDAO.class).withAnyArguments().thenReturn(oAuthConsumerDAO);
        when(oAuthConsumerDAO.getOAuthConsumerSecret(anyString())).thenReturn(consumerSecret);
        when(serviceContext.getProperty(OAUTH_LATEST_TIMESTAMP)).thenReturn(LATEST_TIMESTAMP.toString());
        if (shouldNonceStoreExist) {
            List<String> nonceStore = new ArrayList<>();
            nonceStore.add("an-old-nonce");
            when(serviceContext.getProperty(OAUTH_NONCE_STORE)).thenReturn(nonceStore);
        }
        when(messageContext.getServiceContext()).thenReturn(serviceContext);
        mockStatic(MessageContext.class);
        when(MessageContext.getCurrentMessageContext()).thenReturn(messageContext);
    }

    private void prepareForauthorizeOauthRequestToken(String tenantAwareUserName,
                                                      boolean shouldMakeAuthenticated,
                                                      boolean shouldThrow) throws IdentityException, UserStoreException {

        mockStatic(MultitenantUtils.class);
        when(MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn(tenantAwareUserName);
        when(MultitenantUtils.getTenantDomain(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getRealm(anyString(), anyString())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        if (shouldThrow) {
            when(userStoreManager.authenticate(anyString(), anyString())).thenThrow(UserStoreException.class);
        } else {
            when(userStoreManager.authenticate(anyString(), anyString())).thenReturn(shouldMakeAuthenticated);
        }
    }

    private String getConsumerSignature(Parameters parameters,
                                        String consumerSecret,
                                        String tokenSecret) throws OAuthException {

        GoogleOAuthParameters oauthParameters = new GoogleOAuthParameters();
        oauthParameters.setOAuthConsumerKey(parameters.getOauthConsumerKey());
        oauthParameters.setOAuthConsumerSecret(consumerSecret);
        oauthParameters.setOAuthNonce(parameters.getOauthNonce());
        oauthParameters.setOAuthTimestamp(parameters.getOauthTimeStamp());
        oauthParameters.setOAuthSignatureMethod(parameters.getOauthSignatureMethod());

        if (parameters.getOauthToken() != null) {
            oauthParameters.setOAuthToken(parameters.getOauthToken());
        }

        if (parameters.getOauthTokenVerifier() != null) {
            oauthParameters.setOAuthVerifier((parameters.getOauthTokenVerifier()));
        }

        if (StringUtils.isNotEmpty(tokenSecret)) {
            oauthParameters.setOAuthTokenSecret(tokenSecret);
        }

        OAuthHmacSha1Signer signer = new OAuthHmacSha1Signer();
        String baseString = OAuthUtil.getSignatureBaseString(parameters.getBaseString(), parameters.getHttpMethod(),
                oauthParameters.getBaseParameters());
        return signer.getSignature(baseString, oauthParameters);
    }

    private String getConsumerSignature(OAuthConsumerDTO oAuthConsumer, String consumerSecret) throws OAuthException {

        GoogleOAuthParameters oauthParameters = new GoogleOAuthParameters();
        oauthParameters.setOAuthConsumerKey(oAuthConsumer.getOauthConsumerKey());
        oauthParameters.setOAuthConsumerSecret(consumerSecret);
        oauthParameters.setOAuthNonce(oAuthConsumer.getOauthNonce());
        oauthParameters.setOAuthTimestamp(oAuthConsumer.getOauthTimeStamp());
        oauthParameters.setOAuthSignatureMethod(oAuthConsumer.getOauthSignatureMethod());

        OAuthHmacSha1Signer signer = new OAuthHmacSha1Signer();
        String baseString = OAuthUtil.getSignatureBaseString(oAuthConsumer.getBaseString(),
                oAuthConsumer.getHttpMethod(), oauthParameters.getBaseParameters());
        return signer.getSignature(baseString, oauthParameters);
    }
}
