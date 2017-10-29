/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth2.token.handlers.clientauth;

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.util.Properties;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertTrue;

/**
 * Test Class for the AbstractClientAuthHandler & BasicAuthClientAuthHandler.
 */
@PrepareForTest({
		OAuth2Util.class,
		OAuthServerConfiguration.class
}
)
public class BasicAuthClientAuthHandlerTest extends PowerMockIdentityBaseTest {

	private BasicAuthClientAuthHandler testclass = new BasicAuthClientAuthHandler();

	@DataProvider(name = "provideOAuthTokenReqMessageContext")
	public Object[][] createOAuthTokenReqMessageContext() {

		OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO1 = new OAuth2AccessTokenReqDTO();
		OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO2 = new OAuth2AccessTokenReqDTO();
		OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO3 = new OAuth2AccessTokenReqDTO();
		OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO4 = new OAuth2AccessTokenReqDTO();

		oauth2AccessTokenReqDTO4.setClientSecret("testSecret");

		oauth2AccessTokenReqDTO1.setGrantType("urn:ietf:params:oauth:grant-type:saml2-bearer");
		oauth2AccessTokenReqDTO2.setGrantType("urn:ietf:params:oauth:grant-type:saml2-bearer");
		oauth2AccessTokenReqDTO4.setGrantType("urn:ietf:params:oauth:grant-type:saml2-bearer");

		Properties properties1 = new Properties();
		Properties properties2 = new Properties();
		Properties properties3 = new Properties();
		Properties properties4 = new Properties();
		properties1.setProperty("StrictClientCredentialValidation", "false");
		properties2.setProperty("StrictClientCredentialValidation", "");
		properties3.setProperty("StrictClientCredentialValidation", "false");
		properties4.setProperty("StrictClientCredentialValidation", "false");

		OAuthTokenReqMessageContext tokReqMsgCtx1 = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO1);
		OAuthTokenReqMessageContext tokReqMsgCtx2 = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO2);
		OAuthTokenReqMessageContext tokReqMsgCtx3 = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO3);
		OAuthTokenReqMessageContext tokReqMsgCtx4 = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO4);

		return new Object[][]{
				{tokReqMsgCtx1, true, properties1},
				{tokReqMsgCtx2, false, properties2},
				{tokReqMsgCtx3, false, properties3},
				{tokReqMsgCtx4, false, properties4},
		};

	}

	@Test(dataProvider = "provideOAuthTokenReqMessageContext")
	public void testAuthenticateClient(Object oAuthTokenReqMessageContext, boolean expectedValue,
	                                   Object properties)
			throws InvalidOAuthClientException, IdentityOAuth2Exception, IdentityOAuthAdminException {

		OAuthServerConfiguration oAuthServerConfiguration = mock(OAuthServerConfiguration.class);
		when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(3600L);

		mockStatic(OAuthServerConfiguration.class);
		when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);

		mockStatic(OAuth2Util.class);
		when(OAuth2Util.authenticateClient(anyString(), anyString())).thenReturn(false);
		testclass.init((Properties) properties);
		testclass.authenticateClient((OAuthTokenReqMessageContext) oAuthTokenReqMessageContext);
	}

	@Test(expectedExceptions = IdentityOAuth2Exception.class)
	public void testIdentityOAuthAdminExceptionForAuthenticateClient()
			throws InvalidOAuthClientException, IdentityOAuth2Exception, IdentityOAuthAdminException {

		OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
		OAuthTokenReqMessageContext tokReqMsgCtx1 = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO);
		OAuthServerConfiguration oAuthServerConfiguration = mock(OAuthServerConfiguration.class);
		when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(3600L);

		mockStatic(OAuthServerConfiguration.class);
		when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);

		mockStatic(OAuth2Util.class);
		when(OAuth2Util.authenticateClient(anyString(), anyString()))
				.thenThrow(new IdentityOAuthAdminException(""));
		testclass.authenticateClient(tokReqMsgCtx1);
	}

	@Test(expectedExceptions = IdentityOAuth2Exception.class)
	public void testIdentityInvalidOAuthClientExceptionForAuthenticateClient()
			throws InvalidOAuthClientException, IdentityOAuth2Exception, IdentityOAuthAdminException {

		OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
		OAuthTokenReqMessageContext tokReqMsgCtx1 = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO);
		OAuthServerConfiguration oAuthServerConfiguration = mock(OAuthServerConfiguration.class);
		when(oAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn(3600L);

		mockStatic(OAuthServerConfiguration.class);
		when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);

		mockStatic(OAuth2Util.class);
		when(OAuth2Util.authenticateClient(anyString(), anyString()))
				.thenThrow(new InvalidOAuthClientException(""));
		testclass.authenticateClient(tokReqMsgCtx1);
	}

	@Test
	public void testCanAuthenticate() throws IdentityOAuth2Exception {

		OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
		OAuthTokenReqMessageContext tokReqMsgCtx1 = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO);
		assertFalse(testclass.canAuthenticate(tokReqMsgCtx1));

		oauth2AccessTokenReqDTO.setClientSecret("testSecret");
		OAuthTokenReqMessageContext tokReqMsgCtx3 = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO);
		assertFalse(testclass.canAuthenticate(tokReqMsgCtx3));

		oauth2AccessTokenReqDTO.setClientId("testClientID");
		OAuthTokenReqMessageContext tokReqMsgCtx2 = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO);
		assertTrue(testclass.canAuthenticate(tokReqMsgCtx2));
	}

	@DataProvider(name = "provideProperties")
	public Object[][] createProperties() {

		Properties properties1 = new Properties();
		Properties properties2 = new Properties();
		Properties properties3 = new Properties();
		properties1.setProperty("StrictClientCredentialValidation", "false");
		properties2.setProperty("StrictClientCredentialValidation", "true");
		properties3.setProperty("StrictClientCredentialValidation", "");

		return new Object[][]{
				{properties1, true},
				{properties2, false},
				{properties3, false},
		};

	}

	@Test(dataProvider = "provideProperties")
	public void testCanAuthenticateInElse(Object properties, boolean expectedvalue) throws IdentityOAuth2Exception {

		OAuth2AccessTokenReqDTO oauth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
		oauth2AccessTokenReqDTO.setGrantType("urn:ietf:params:oauth:grant-type:saml2-bearer");
		testclass.init((Properties) properties);
		OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(oauth2AccessTokenReqDTO);
		assertEquals(testclass.canAuthenticate(tokReqMsgCtx), expectedvalue);
	}

}
