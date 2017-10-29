package org.wso2.carbon.identity.oauth2.token.handlers.grant.iwa.ntlm;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.*;

@PrepareForTest({ OAuthServerConfiguration.class})
public class NTLMAuthenticationGrantHandlerWithHandshakeTest {

    private static String TOKEN = "c2Fkc2Fkc2FzYWQzMmQzMmQzMmUyM2UzMmUzMjIzZTMyZTMyZTMyZDI=";

    @Mock
    private OAuthServerConfiguration serverConfiguration;
    @BeforeMethod
    public void setUp() throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        MockitoAnnotations.initMocks(this);
        when(OAuthServerConfiguration.getInstance()).thenReturn(serverConfiguration);
    }

    @Test
    public void testGetNLTMMessageType() throws Exception {


    }

    @DataProvider
    public Object[][] getValidateGrantData() {
        return new Object[][] {
                { null }, { TOKEN }
        };
    }

    @Test(dataProvider = "getValidateGrantData")
    public void testValidateGrant(String token) throws Exception {
        NTLMAuthenticationGrantHandlerWithHandshake ntlmAuthenticationGrantHandlerWithHandshake = new
                NTLMAuthenticationGrantHandlerWithHandshake();
        OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
        oAuth2AccessTokenReqDTO.setWindowsToken(token);
        OAuthTokenReqMessageContext oAuthTokenReqMessageContext = new OAuthTokenReqMessageContext(oAuth2AccessTokenReqDTO);
        ntlmAuthenticationGrantHandlerWithHandshake.validateGrant(oAuthTokenReqMessageContext);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

}