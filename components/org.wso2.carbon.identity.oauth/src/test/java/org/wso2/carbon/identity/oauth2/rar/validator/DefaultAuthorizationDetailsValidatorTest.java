package org.wso2.carbon.identity.oauth2.rar.validator;

import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ServerException;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.rar.exception.AuthorizationDetailsProcessingException;
import org.wso2.carbon.identity.oauth2.rar.utils.AuthorizationDetailsBaseTest;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.oauth2.TestConstants.ACESS_TOKEN_ID;
import static org.wso2.carbon.identity.oauth2.TestConstants.TENANT_ID;

public class DefaultAuthorizationDetailsValidatorTest extends AuthorizationDetailsBaseTest {

    AuthorizationDetailsValidator uut;

    @BeforeClass
    public void setUp() throws IdentityOAuth2Exception {
        when(serviceMock.getAccessTokenAuthorizationDetails(ACESS_TOKEN_ID, TENANT_ID))
                .thenReturn(authorizationDetails);

        this.uut = new DefaultAuthorizationDetailsValidator(processorFactoryMock, serviceMock, schemaValidatorMock);
    }

    @Test
    public void shouldReturnContextAuthorizationDetails_ifGrantTypeIsAuthzCode()
            throws IdentityOAuth2ServerException, AuthorizationDetailsProcessingException {

        OAuth2AccessTokenReqDTO reqDTO = new OAuth2AccessTokenReqDTO();
        reqDTO.setGrantType(GrantType.AUTHORIZATION_CODE.toString());

        OAuthTokenReqMessageContext messageContext = new OAuthTokenReqMessageContext(reqDTO);
        messageContext.setAuthorizationDetails(authorizationDetails);

        assertEquals(authorizationDetails, uut.getValidatedAuthorizationDetails(messageContext));
    }

    @Test
    public void shouldReturnContextAuthorizationDetails_ifNoNewAuthorizationDetailsRequested()
            throws IdentityOAuth2ServerException, AuthorizationDetailsProcessingException {

        OAuthTokenReqMessageContext messageContext = new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO());
        messageContext.setAuthorizationDetails(authorizationDetails);

        assertEquals(authorizationDetails, uut.getValidatedAuthorizationDetails(messageContext));
    }
}
