package org.wso2.carbon.identity.oauth2.validators;

import org.mockito.Mock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.test.common.testNg.WithAxisConfiguration;
import org.wso2.carbon.identity.test.common.testNg.WithCarbonHome;
import org.wso2.carbon.identity.test.common.testNg.WithH2Database;

import static org.testng.Assert.assertNotNull;

@WithCarbonHome
@WithAxisConfiguration
@WithH2Database(jndiName = "jdbc/WSO2IdentityDB", files = {"dbScripts/token.sql"})
public class TokenValidationHandlerTest {

    @Mock
    private OAuth2TokenValidator tokenValidator;
    private TokenValidationHandler tokenValidationHandler;

    @BeforeMethod
    public void setUp() {
        tokenValidationHandler = TokenValidationHandler.getInstance();
        tokenValidationHandler.addTokenValidator("test", tokenValidator);
    }

    @Test
    public void testGetInstance() throws Exception {
        assertNotNull(tokenValidationHandler);
    }

    @Test
    public void testValidate() throws Exception {
        OAuth2TokenValidationResponseDTO responseDTO = tokenValidationHandler
                .validate(new OAuth2TokenValidationRequestDTO());
        assertNotNull(responseDTO);
    }

    @Test
    public void testFindOAuthConsumerIfTokenIsValid() throws Exception {
        OAuth2TokenValidationRequestDTO oAuth2TokenValidationRequestDTO = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken oAuth2AccessToken = oAuth2TokenValidationRequestDTO.new OAuth2AccessToken();
        oAuth2AccessToken.setIdentifier("identifier");
        oAuth2AccessToken.setTokenType("bearer");
        oAuth2TokenValidationRequestDTO.setAccessToken(oAuth2AccessToken);

        OAuth2ClientApplicationDTO response = tokenValidationHandler
                .findOAuthConsumerIfTokenIsValid(oAuth2TokenValidationRequestDTO);
        assertNotNull(response);
    }

    @Test
    public void testBuildIntrospectionResponse() throws Exception {
    }

}
