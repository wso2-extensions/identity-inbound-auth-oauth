package org.wso2.carbon.identity.oauth2.rar.token;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.rar.utils.AuthorizationDetailsBaseTest;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

/**
 * Test class for {@link AccessTokenResponseRARHandler}.
 */
public class AccessTokenResponseRARHandlerTest extends AuthorizationDetailsBaseTest {

    private AccessTokenResponseRARHandler uut;

    @BeforeClass
    public void setUp() {
        this.uut = new AccessTokenResponseRARHandler();
    }

    @Test
    public void shouldReturnAuthorizationDetails_ifRichAuthorizationRequest() throws IdentityOAuth2Exception {

        assertAuthorizationDetailsPresent(uut.getAdditionalTokenResponseAttributes(tokenReqMessageContext));
    }

    @Test
    public void shouldReturnEmpty_ifNotRichAuthorizationRequest() throws IdentityOAuth2Exception {

        OAuthTokenReqMessageContext messageContext = new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO());
        assertAuthorizationDetailsMissing(uut.getAdditionalTokenResponseAttributes(messageContext));
    }
}
