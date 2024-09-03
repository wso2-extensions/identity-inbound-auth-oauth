package org.wso2.carbon.identity.oauth2.rar.token;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.rar.utils.AuthorizationDetailsBaseTest;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

public class JWTAccessTokenRARClaimProviderTest extends AuthorizationDetailsBaseTest {

    private JWTAccessTokenRARClaimProvider uut;

    @BeforeClass
    public void setUp() {
        this.uut = new JWTAccessTokenRARClaimProvider();
    }

    @Test
    public void shouldReturnEmptyForAuthzReq_ifNotRichAuthorizationRequest() throws IdentityOAuth2Exception {

        OAuthAuthzReqMessageContext messageContext = new OAuthAuthzReqMessageContext(new OAuth2AuthorizeReqDTO());
        assertAuthorizationDetailsMissing(uut.getAdditionalClaims(messageContext));
    }

    @Test
    public void shouldReturnEmptyForTokenReq_ifNotRichAuthorizationRequest() throws IdentityOAuth2Exception {

        OAuthTokenReqMessageContext messageContext = new OAuthTokenReqMessageContext(new OAuth2AccessTokenReqDTO());

        assertAuthorizationDetailsMissing(uut.getAdditionalClaims(messageContext));
    }

    @Test
    public void shouldReturnAuthorizationDetailsForAuthzReq_ifNotRichAuthorizationRequest()
            throws IdentityOAuth2Exception {

        assertAuthorizationDetailsPresent(uut.getAdditionalClaims(authzReqMessageContext));
    }

    @Test
    public void shouldReturnAuthorizationDetailsForTokenReq_ifNotRichAuthorizationRequest()
            throws IdentityOAuth2Exception {

        assertAuthorizationDetailsPresent(uut.getAdditionalClaims(tokenReqMessageContext));
    }
}
