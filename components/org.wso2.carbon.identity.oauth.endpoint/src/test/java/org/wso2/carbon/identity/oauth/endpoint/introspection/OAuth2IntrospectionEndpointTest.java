package org.wso2.carbon.identity.oauth.endpoint.introspection;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import javax.ws.rs.core.Response;
import java.nio.file.Paths;
import java.util.HashMap;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyVararg;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.AssertJUnit.assertEquals;

@PrepareForTest ( {PrivilegedCarbonContext.class} )
public class OAuth2IntrospectionEndpointTest extends PowerMockIdentityBaseTest {

    @Mock
    OAuth2IntrospectionResponseDTO mockedIntrospectionResponse;

    @Mock
    PrivilegedCarbonContext mockedPrivilegedCarbonContext;


    private static final String CLAIM_SEPARATOR = ",";
    private static final String USERNAME_CLAIM_URI = "http://wso2.org/claims/username";
    private static final String EMAIL_CLAIM_URI = "http://wso2.org/claims/emailaddress";
    private static final String ROLE_CLAIM_URI = "http://wso2.org/claims/role";
    private static final String BEARER_TOKEN_TYPE_HINT = "bearer";

    private OAuth2IntrospectionEndpoint oAuth2IntrospectionEndpoint;

    @BeforeTest
    public void setUp() {

        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
        );
        oAuth2IntrospectionEndpoint = new OAuth2IntrospectionEndpoint();
    }

    @Test(dataProvider = "provideTokenInfo")
    public void testTokenTypeHint(String tokenTypeHint, String expectedTokenType) {

        String token = "TOKEN";
        String[] claims = new String[]{USERNAME_CLAIM_URI, EMAIL_CLAIM_URI, ROLE_CLAIM_URI};
        String requiredClaims = String.join(CLAIM_SEPARATOR, claims);

        OAuth2TokenValidationService mockedTokenService = mock(OAuth2TokenValidationService.class);

        mockStatic(PrivilegedCarbonContext.class);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext()).thenReturn(mockedPrivilegedCarbonContext);
        when(mockedPrivilegedCarbonContext.getOSGiService(any())).
                thenReturn(mockedTokenService);

        when(mockedTokenService.buildIntrospectionResponse(anyVararg()))
                .thenReturn(mockedIntrospectionResponse);

        when(mockedIntrospectionResponse.getError()).thenReturn(null);
        mockedIntrospectionResponse.setTokenType(expectedTokenType);

        when(mockedIntrospectionResponse.getTokenType()).thenReturn(expectedTokenType);

        Response response = oAuth2IntrospectionEndpoint.introspect(token, tokenTypeHint, requiredClaims);

        HashMap<String,String> map = new Gson().fromJson((String)response.getEntity(), new TypeToken<HashMap<String,
                String>>(){}.getType());

        assertEquals(map.get("token_type"), expectedTokenType);


    }

    @DataProvider(name = "provideTokenInfo")
    public Object[][] provideTokenInfo() {

        return new Object[][] {
                {BEARER_TOKEN_TYPE_HINT, "Bearer"},
                {BEARER_TOKEN_TYPE_HINT, "JWT"}
        };
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}
