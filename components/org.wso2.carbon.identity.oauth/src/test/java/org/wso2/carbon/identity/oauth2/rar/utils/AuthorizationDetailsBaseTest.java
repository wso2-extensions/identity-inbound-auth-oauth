package org.wso2.carbon.identity.oauth2.rar.utils;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.rar.AuthorizationDetailsSchemaValidator;
import org.wso2.carbon.identity.oauth2.rar.AuthorizationDetailsService;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProcessor;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProcessorFactory;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth2.rar.util.AuthorizationDetailsConstants;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth2.TestConstants.ACESS_TOKEN_ID;
import static org.wso2.carbon.identity.oauth2.TestConstants.CLIENT_ID;
import static org.wso2.carbon.identity.oauth2.TestConstants.TENANT_DOMAIN;
import static org.wso2.carbon.identity.oauth2.TestConstants.TENANT_ID;
import static org.wso2.carbon.identity.oauth2.TestConstants.TEST_TYPE;
import static org.wso2.carbon.identity.oauth2.TestConstants.TEST_USER_ID;

public class AuthorizationDetailsBaseTest {

    protected AuthorizationDetail authorizationDetail;
    protected AuthorizationDetails authorizationDetails;
    protected OAuthAuthzReqMessageContext authzReqMessageContext;
    protected OAuthTokenReqMessageContext tokenReqMessageContext;
    protected OAuth2TokenValidationRequestDTO tokenValidationRequestDTO;
    protected OAuth2IntrospectionResponseDTO introspectionResponseDTO;
    protected AuthenticatedUser authenticatedUser;
    protected OAuth2Parameters oAuth2Parameters;
    protected AccessTokenDO accessTokenDO;
    protected OAuth2AccessTokenReqDTO accessTokenReqDTO;

    protected AuthorizationDetailsProcessorFactory processorFactoryMock;
    protected AuthorizationDetailsService serviceMock;

    protected AuthorizationDetailsSchemaValidator schemaValidatorMock;

    public AuthorizationDetailsBaseTest() {

        this.authorizationDetail = new AuthorizationDetail();
        this.authorizationDetail.setType(TEST_TYPE);

        this.authorizationDetails = new AuthorizationDetails(Collections.singleton(this.authorizationDetail));

        final OAuth2AuthorizeReqDTO authorizeReqDTO = new OAuth2AuthorizeReqDTO();
        authorizeReqDTO.setConsumerKey(CLIENT_ID);
        authorizeReqDTO.setTenantDomain(TENANT_DOMAIN);
        authorizeReqDTO.setAuthorizationDetails(this.authorizationDetails);

        this.authzReqMessageContext = new OAuthAuthzReqMessageContext(authorizeReqDTO);
        this.authzReqMessageContext.setAuthorizationDetails(this.authorizationDetails);

        this.accessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        this.accessTokenReqDTO.setAuthorizationDetails(authorizationDetails);

        this.tokenReqMessageContext = new OAuthTokenReqMessageContext(this.accessTokenReqDTO);
        this.tokenReqMessageContext.setAuthorizationDetails(this.authorizationDetails);

        this.tokenValidationRequestDTO = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken accessToken =
                this.tokenValidationRequestDTO.new OAuth2AccessToken();
        accessToken.setIdentifier(ACESS_TOKEN_ID);
        this.tokenValidationRequestDTO.setAccessToken(accessToken);

        this.introspectionResponseDTO = new OAuth2IntrospectionResponseDTO();

        this.authenticatedUser = new AuthenticatedUser();
        this.authenticatedUser.setUserId(TEST_USER_ID);

        this.oAuth2Parameters = new OAuth2Parameters();
        this.oAuth2Parameters.setTenantDomain(TENANT_DOMAIN);
        this.oAuth2Parameters.setAuthorizationDetails(this.authorizationDetails);
        this.oAuth2Parameters.setClientId(CLIENT_ID);

        this.accessTokenDO = new AccessTokenDO();
        this.accessTokenDO.setTokenId(ACESS_TOKEN_ID);
        this.accessTokenDO.setTenantID(TENANT_ID);

        mockAuthorizationDetailsProviderFactory();
        this.serviceMock = mock(AuthorizationDetailsService.class);

        this.schemaValidatorMock = spy(AuthorizationDetailsSchemaValidator.class);
    }

    public static void assertAuthorizationDetailsPresent(final Map<String, Object> attributes) {

        assertTrue(attributes.containsKey(AuthorizationDetailsConstants.AUTHORIZATION_DETAILS));
        assertEquals(((Set<AuthorizationDetail>)
                attributes.get(AuthorizationDetailsConstants.AUTHORIZATION_DETAILS)).size(), 1);
    }

    public static void assertAuthorizationDetailsMissing(final Map<String, Object> attributes) {

        assertFalse(attributes.containsKey(AuthorizationDetailsConstants.AUTHORIZATION_DETAILS));
    }

    private void mockAuthorizationDetailsProviderFactory() {

        this.processorFactoryMock = spy(AuthorizationDetailsProcessorFactory.class);
        try {
            Field privateField = AuthorizationDetailsProcessorFactory.class
                    .getDeclaredField("authorizationDetailsProcessors");
            privateField.setAccessible(true);

            privateField.set(this.processorFactoryMock, new HashMap<String, AuthorizationDetailsProcessor>() {{
                put(TEST_TYPE, getAuthorizationDetailsProcessorMock());
            }});
        } catch (Exception e) {
            // ignores the exceptions
        }
    }

    private AuthorizationDetailsProcessor getAuthorizationDetailsProcessorMock() {
        final AuthorizationDetailsProcessor processorMock = mock(AuthorizationDetailsProcessor.class);
        when(processorMock.getType()).thenReturn(TEST_TYPE);
        when(processorMock.isEqualOrSubset(any(AuthorizationDetail.class), any(AuthorizationDetails.class)))
                .thenAnswer(invocation -> {
                    AuthorizationDetail ad = invocation.getArgument(0, AuthorizationDetail.class);
                    AuthorizationDetails ads = invocation.getArgument(1, AuthorizationDetails.class);

                    return ads.stream().map(AuthorizationDetail::getType).allMatch(type -> type.equals(ad.getType()));
                });
        return processorMock;
    }
}
