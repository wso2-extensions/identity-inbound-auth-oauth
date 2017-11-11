/*
* Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package org.wso2.carbon.identity.oauth2.authz;

import org.apache.oltu.oauth2.common.error.OAuthError;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;

@WithCarbonHome
@WithH2Database(files = {"dbScripts/h2_with_application_and_token.sql"})
@WithRealmService(tenantId = TestConstants.TENANT_ID, tenantDomain = TestConstants.TENANT_DOMAIN,
        initUserStoreManager = true, injectToSingletons = {OAuthComponentServiceHolder.class})
public class AuthorizationHandlerManagerTest extends IdentityBaseTest {

    private AuthorizationHandlerManager authorizationHandlerManager;
    private OAuth2AuthorizeReqDTO authzReqDTO = new OAuth2AuthorizeReqDTO();

    @BeforeClass
    public void setUp() throws Exception {
        authorizationHandlerManager = AuthorizationHandlerManager.getInstance();
    }

    @Test
    public void testHandleAuthorizationIDTokenTokenResponse() throws Exception {
        authorizationHandlerManager = AuthorizationHandlerManager.getInstance();
        authzReqDTO.setResponseType(TestConstants.AUTHORIZATION_HANDLER_RESPONSE_TYPE_ID_TOKEN_TOKEN);
        authzReqDTO.setConsumerKey(TestConstants.CLIENT_ID);
        authzReqDTO.setScopes(TestConstants.SCOPE_STRING.split(" "));
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(TestConstants.USER_NAME);
        user.setTenantDomain(TestConstants.TENANT_DOMAIN);
        user.setUserStoreDomain(TestConstants.USER_DOMAIN_PRIMARY);
        authzReqDTO.setUser(user);
        OAuth2AuthorizeRespDTO respDTO = authorizationHandlerManager.handleAuthorization(authzReqDTO);
        Assert.assertNotNull(respDTO, "Response is null");
        Assert.assertNotNull(respDTO.getAccessToken(), "Access token returned is null");
    }

    @Test
    public void testHandleAuthorizationIDTokenTokenResponseTypeUnauthorized() throws Exception {
        authzReqDTO.setResponseType(TestConstants.AUTHORIZATION_HANDLER_RESPONSE_TYPE_ID_TOKEN_TOKEN);
        authzReqDTO.setConsumerKey(TestConstants.CLIENT_ID_UNAUTHORIZED_CLIENT);
        authzReqDTO.setScopes(TestConstants.SCOPE_STRING.split(" "));
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(TestConstants.USER_NAME);
        user.setTenantDomain(TestConstants.TENANT_DOMAIN);
        user.setUserStoreDomain(TestConstants.USER_DOMAIN_PRIMARY);
        authzReqDTO.setUser(user);
        OAuth2AuthorizeRespDTO respDTO = authorizationHandlerManager.handleAuthorization(authzReqDTO);
        String errorCode = respDTO.getErrorCode();
        Assert.assertNotNull(respDTO, "Response is null");
        Assert.assertNotNull(respDTO.getErrorCode(), "Error code returned is null");
        Assert.assertEquals(errorCode, TestConstants.UNAUTHORIZED_CLIENT_ERROR_CODE,
                            "Expected unauthorized_client error code but found : " + errorCode);
    }

    @Test
    public void testHandleAuthorizationIDTokenResponse() throws Exception {
        authorizationHandlerManager = AuthorizationHandlerManager.getInstance();
        authzReqDTO.setResponseType(TestConstants.AUTHORIZATION_HANDLER_RESPONSE_TYPE_ID_TOKEN);
        authzReqDTO.setConsumerKey(TestConstants.CLIENT_ID);
        authzReqDTO.setScopes(TestConstants.SCOPE_STRING.split(" "));
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(TestConstants.USER_NAME);
        user.setTenantDomain(TestConstants.TENANT_DOMAIN);
        user.setUserStoreDomain(TestConstants.USER_DOMAIN_PRIMARY);
        authzReqDTO.setUser(user);
        OAuth2AuthorizeRespDTO respDTO = authorizationHandlerManager.handleAuthorization(authzReqDTO);
        Assert.assertNotNull(respDTO, "Response is null");
        Assert.assertNotNull(respDTO.getAccessToken(), "ID token returned is null");
    }

    @Test
    public void testHandleAuthorizationIDTokenResponseTypeUnauthorized() throws Exception {
        authzReqDTO.setResponseType(TestConstants.AUTHORIZATION_HANDLER_RESPONSE_TYPE_ID_TOKEN);
        authzReqDTO.setConsumerKey(TestConstants.CLIENT_ID_UNAUTHORIZED_CLIENT);
        authzReqDTO.setScopes(TestConstants.SCOPE_STRING.split(" "));
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(TestConstants.USER_NAME);
        user.setTenantDomain(TestConstants.TENANT_DOMAIN);
        user.setUserStoreDomain(TestConstants.USER_DOMAIN_PRIMARY);
        authzReqDTO.setUser(user);
        OAuth2AuthorizeRespDTO respDTO = authorizationHandlerManager.handleAuthorization(authzReqDTO);
        String errorCode = respDTO.getErrorCode();
        Assert.assertNotNull(respDTO, "Response is null");
        Assert.assertNotNull(respDTO.getErrorCode(), "Error code returned is null");
        Assert.assertEquals(errorCode, TestConstants.UNAUTHORIZED_CLIENT_ERROR_CODE,
                            "Expected unauthorized_client error code but found : " + errorCode);
    }

    @Test
    public void testHandleAuthorizationTokenResponse() throws Exception {
        authorizationHandlerManager = AuthorizationHandlerManager.getInstance();
        authzReqDTO.setResponseType(TestConstants.AUTHORIZATION_HANDLER_RESPONSE_TYPE_TOKEN);
        authzReqDTO.setConsumerKey(TestConstants.CLIENT_ID);
        authzReqDTO.setScopes(TestConstants.SCOPE_STRING.split(" "));
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(TestConstants.USER_NAME);
        user.setTenantDomain(TestConstants.TENANT_DOMAIN);
        user.setUserStoreDomain(TestConstants.USER_DOMAIN_PRIMARY);
        authzReqDTO.setUser(user);
        OAuth2AuthorizeRespDTO respDTO = authorizationHandlerManager.handleAuthorization(authzReqDTO);
        Assert.assertNotNull(respDTO, "Response is null");
        Assert.assertNotNull(respDTO.getAccessToken(), "Access token returned is null");
    }

    @Test
    public void testHandleAuthorizationTokenResponseTypeUnauthorized() throws Exception {
        authzReqDTO.setResponseType(TestConstants.AUTHORIZATION_HANDLER_RESPONSE_TYPE_TOKEN);
        authzReqDTO.setConsumerKey(TestConstants.CLIENT_ID_UNAUTHORIZED_CLIENT);
        authzReqDTO.setScopes(TestConstants.SCOPE_STRING.split(" "));
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(TestConstants.USER_NAME);
        user.setTenantDomain(TestConstants.TENANT_DOMAIN);
        user.setUserStoreDomain(TestConstants.USER_DOMAIN_PRIMARY);
        authzReqDTO.setUser(user);
        OAuth2AuthorizeRespDTO respDTO = authorizationHandlerManager.handleAuthorization(authzReqDTO);
        String errorCode = respDTO.getErrorCode();
        Assert.assertNotNull(respDTO, "Response is null");
        Assert.assertNotNull(respDTO.getErrorCode(), "Error code returned is null");
        Assert.assertEquals(errorCode, TestConstants.UNAUTHORIZED_CLIENT_ERROR_CODE,
                            "Expected unauthorized_client error code but found : " + errorCode);
    }

    @Test
    public void testHandleAuthorizationCodeResponse() throws Exception {
        authorizationHandlerManager = AuthorizationHandlerManager.getInstance();
        authzReqDTO.setResponseType(TestConstants.AUTHORIZATION_HANDLER_RESPONSE_TYPE_CODE);
        authzReqDTO.setConsumerKey(TestConstants.CLIENT_ID);
        authzReqDTO.setScopes(TestConstants.SCOPE_STRING.split(" "));
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(TestConstants.USER_NAME);
        user.setTenantDomain(TestConstants.TENANT_DOMAIN);
        user.setUserStoreDomain(TestConstants.USER_DOMAIN_PRIMARY);
        authzReqDTO.setUser(user);
        OAuth2AuthorizeRespDTO respDTO = authorizationHandlerManager.handleAuthorization(authzReqDTO);
        Assert.assertNotNull(respDTO, "Response is null");
        Assert.assertNotNull(respDTO.getAuthorizationCode(), "Code returned is null");
    }

    @Test
    public void testHandleAuthorizationCodeResponseTypeUnauthorized() throws Exception {
        authzReqDTO.setResponseType(TestConstants.AUTHORIZATION_HANDLER_RESPONSE_TYPE_CODE);
        authzReqDTO.setConsumerKey(TestConstants.CLIENT_ID_UNAUTHORIZED_CLIENT);
        authzReqDTO.setScopes(TestConstants.SCOPE_STRING.split(" "));
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(TestConstants.USER_NAME);
        user.setTenantDomain(TestConstants.TENANT_DOMAIN);
        user.setUserStoreDomain(TestConstants.USER_DOMAIN_PRIMARY);
        authzReqDTO.setUser(user);
        OAuth2AuthorizeRespDTO respDTO = authorizationHandlerManager.handleAuthorization(authzReqDTO);
        String errorCode = respDTO.getErrorCode();
        Assert.assertNotNull(respDTO, "Response is null");
        Assert.assertNotNull(respDTO.getErrorCode(), "Error code returned is null");
        Assert.assertEquals(errorCode, TestConstants.UNAUTHORIZED_CLIENT_ERROR_CODE,
                            "Expected unauthorized_client error code but found : " + errorCode);
    }

    @Test
    public void testHandleInvalidResponseType() throws Exception {
        authzReqDTO.setResponseType(TestConstants.AUTHORIZATION_HANDLER_RESPONSE_TYPE_INVALID);
        OAuth2AuthorizeRespDTO respDTO = authorizationHandlerManager.handleAuthorization(authzReqDTO);
        String errorCode = respDTO.getErrorCode();
        Assert.assertNotNull(respDTO, "Response is null");
        Assert.assertNotNull(respDTO.getErrorCode(), "Error code returned is null");
        Assert.assertEquals(errorCode, OAuthError.CodeResponse.UNSUPPORTED_RESPONSE_TYPE,
                            "Expected " + OAuthError.CodeResponse.UNSUPPORTED_RESPONSE_TYPE +
                            " error code but found : " + errorCode);
    }

    @Test
    public void testHandleAuthorizationTokenResponseNoScopes() throws Exception {
        authorizationHandlerManager = AuthorizationHandlerManager.getInstance();
        authzReqDTO.setResponseType(TestConstants.AUTHORIZATION_HANDLER_RESPONSE_TYPE_TOKEN);
        authzReqDTO.setConsumerKey(TestConstants.CLIENT_ID);
        authzReqDTO.setScopes(new String[0]);
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(TestConstants.USER_NAME);
        user.setTenantDomain(TestConstants.TENANT_DOMAIN);
        user.setUserStoreDomain(TestConstants.USER_DOMAIN_PRIMARY);
        authzReqDTO.setUser(user);
        OAuth2AuthorizeRespDTO respDTO = authorizationHandlerManager.handleAuthorization(authzReqDTO);
        Assert.assertNotNull(respDTO, "Response is null");
        Assert.assertNotNull(respDTO.getAccessToken(), "Access token returned is null");
    }

    @Test
    public void testHandleAuthorizationTokenResponseUnauthorizedAccess() throws Exception {
        authorizationHandlerManager = AuthorizationHandlerManager.getInstance();
        authzReqDTO.setResponseType(TestConstants.AUTHORIZATION_HANDLER_RESPONSE_TYPE_TOKEN);
        authzReqDTO.setConsumerKey(TestConstants.CLIENT_ID);
        authzReqDTO.setScopes(TestConstants.SCOPE_UNAUTHORIZED_ACCESS.split(" "));
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(TestConstants.USER_NAME);
        user.setTenantDomain(TestConstants.TENANT_DOMAIN);
        user.setUserStoreDomain(TestConstants.USER_DOMAIN_PRIMARY);
        authzReqDTO.setUser(user);
        OAuth2AuthorizeRespDTO respDTO = authorizationHandlerManager.handleAuthorization(authzReqDTO);
        String errorCode = respDTO.getErrorCode();
        Assert.assertNotNull(respDTO, "Response is null");
        Assert.assertNotNull(respDTO.getErrorCode(), "Error code returned is null");
        Assert.assertEquals(errorCode, OAuthError.CodeResponse.UNAUTHORIZED_CLIENT,
                            "Expected " + OAuthError.CodeResponse.UNAUTHORIZED_CLIENT + " error code but found : " +
                            errorCode);
    }

    @Test
    public void testHandleAuthorizationTokenResponseUnauthorizedScope() throws Exception {
        authorizationHandlerManager = AuthorizationHandlerManager.getInstance();
        authzReqDTO.setResponseType(TestConstants.AUTHORIZATION_HANDLER_RESPONSE_TYPE_TOKEN);
        authzReqDTO.setConsumerKey(TestConstants.CLIENT_ID);
        authzReqDTO.setScopes(TestConstants.SCOPE_UNAUTHORIZED_SCOPE.split(" "));
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(TestConstants.USER_NAME);
        user.setTenantDomain(TestConstants.TENANT_DOMAIN);
        user.setUserStoreDomain(TestConstants.USER_DOMAIN_PRIMARY);
        authzReqDTO.setUser(user);
        OAuth2AuthorizeRespDTO respDTO = authorizationHandlerManager.handleAuthorization(authzReqDTO);
        String errorCode = respDTO.getErrorCode();
        Assert.assertNotNull(respDTO, "Response is null");
        Assert.assertNotNull(respDTO.getErrorCode(), "Error code returned is null");
        Assert.assertEquals(errorCode, OAuthError.CodeResponse.INVALID_SCOPE,
                            "Expected " + OAuthError.CodeResponse.INVALID_SCOPE + " error code but found : " +
                            errorCode);
    }

}
