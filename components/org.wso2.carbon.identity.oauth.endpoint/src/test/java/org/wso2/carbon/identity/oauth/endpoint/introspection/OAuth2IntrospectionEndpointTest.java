package org.wso2.carbon.identity.oauth.endpoint.introspection;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.core.Response;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.anyVararg;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.AssertJUnit.assertEquals;

@PrepareForTest({PrivilegedCarbonContext.class, LoggerUtils.class, IdentityTenantUtil.class,
        OAuthServerConfiguration.class, TokenPersistenceProcessor.class})
public class OAuth2IntrospectionEndpointTest extends PowerMockIdentityBaseTest {

    @Mock
    OAuth2IntrospectionResponseDTO mockedIntrospectionResponse;

    @Mock
    PrivilegedCarbonContext mockedPrivilegedCarbonContext;

    @Mock
    OAuthServerConfiguration oAuthServerConfiguration;

    @Mock
    TokenPersistenceProcessor tokenPersistenceProcessor;

    private static final String CLAIM_SEPARATOR = ",";
    private static final String USERNAME_CLAIM_URI = "http://wso2.org/claims/username";
    private static final String EMAIL_CLAIM_URI = "http://wso2.org/claims/emailaddress";
    private static final String ROLE_CLAIM_URI = "http://wso2.org/claims/role";
    private static final String BEARER_TOKEN_TYPE_HINT = "bearer";

    private OAuth2IntrospectionEndpoint oAuth2IntrospectionEndpoint;

    @BeforeClass
    public void setUp() {

        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
                          );
        oAuth2IntrospectionEndpoint = new OAuth2IntrospectionEndpoint();
    }

    @Test(dataProvider = "provideTokenInfo")
    public void testTokenTypeHint(String tokenTypeHint, String expectedTokenType) throws Exception {

        String token = "TOKEN";
        String[] claims = new String[]{USERNAME_CLAIM_URI, EMAIL_CLAIM_URI, ROLE_CLAIM_URI};
        String requiredClaims = String.join(CLAIM_SEPARATOR, claims);

        OAuth2TokenValidationService mockedTokenService = mock(OAuth2TokenValidationService.class);

        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantDomain(anyInt())).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);
        mockOAuthServerConfiguration();
        mockStatic(PrivilegedCarbonContext.class);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext()).thenReturn(mockedPrivilegedCarbonContext);
        when(mockedPrivilegedCarbonContext.getOSGiService(any())).
                thenReturn(mockedTokenService);

        when(mockedTokenService.buildIntrospectionResponse(anyVararg()))
                .thenReturn(mockedIntrospectionResponse);

        when(mockedIntrospectionResponse.getError()).thenReturn(null);
        mockedIntrospectionResponse.setTokenType(expectedTokenType);

        when(mockedIntrospectionResponse.getTokenType()).thenReturn(expectedTokenType);
        when(mockedIntrospectionResponse.getBindingType())
                .thenReturn(OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER);
        when(mockedIntrospectionResponse.getBindingReference())
                .thenReturn("test_reference_value");
        when(mockedIntrospectionResponse.getCnfBindingValue())
                .thenReturn("R4Hj_0nNdIzVvPdCdsWlxNKm6a74cszp4Za4M1iE8P9");

        Response response = oAuth2IntrospectionEndpoint.introspect(token, tokenTypeHint, requiredClaims);

        HashMap<String, Object> map = new Gson().fromJson((String) response.getEntity(), new TypeToken<HashMap<String,
                Object>>() {
        }.getType());

        assertEquals(map.get("token_type"), expectedTokenType);
        assertEquals(map.get("binding_type"), OAuth2Constants.TokenBinderType.CERTIFICATE_BASED_TOKEN_BINDER);
        assertEquals(map.get("binding_ref"), "test_reference_value");
        assertEquals(((Map<String, String>) map.get(OAuthConstants.CNF))
                        .get(OAuthConstants.X5T_S256), "R4Hj_0nNdIzVvPdCdsWlxNKm6a74cszp4Za4M1iE8P9");

    }

    private void mockOAuthServerConfiguration() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oAuthServerConfiguration);
        when(oAuthServerConfiguration.getPersistenceProcessor()).thenReturn(tokenPersistenceProcessor);
        when(oAuthServerConfiguration.isRedirectToRequestedRedirectUriEnabled()).thenReturn(false);
        when(tokenPersistenceProcessor.getProcessedClientId(anyString())).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocation) {

                return invocation.getArguments()[0];
            }
        });
    }

    @DataProvider(name = "provideTokenInfo")
    public Object[][] provideTokenInfo() {

        return new Object[][]{
                {BEARER_TOKEN_TYPE_HINT, "Bearer"},
                {BEARER_TOKEN_TYPE_HINT, "JWT"}
        };
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}
