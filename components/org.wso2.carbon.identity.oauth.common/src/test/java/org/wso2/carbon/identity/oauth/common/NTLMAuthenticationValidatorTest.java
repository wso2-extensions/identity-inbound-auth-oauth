package org.wso2.carbon.identity.oauth.common;

import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Test class for NTLMAuthenticationValidator.
 */
public class NTLMAuthenticationValidatorTest {

    private NTLMAuthenticationValidator testedValidator;

    @BeforeMethod
    public void setUp() throws Exception {
        testedValidator = new NTLMAuthenticationValidator();
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    @DataProvider(name = "Request Provider")
    public Object[][] getRequestParams() {
        Map<String, String> allParamPresentMap = new HashMap<>();
        allParamPresentMap.put(OAuth.OAUTH_GRANT_TYPE, GrantType.IWA_NTLM.toString());
        allParamPresentMap.put(OAuthConstants.WINDOWS_TOKEN, "ntlm_token");

        Map<String, String> blankGrantTypeMap = new HashMap<>();
        blankGrantTypeMap.put(OAuth.OAUTH_GRANT_TYPE, StringUtils.EMPTY);
        blankGrantTypeMap.put(OAuthConstants.WINDOWS_TOKEN, "ntlm_token");
        Map<String, String> nullGrantTypeMap = new HashMap<>();
        nullGrantTypeMap.put(OAuth.OAUTH_GRANT_TYPE, null);
        nullGrantTypeMap.put(OAuthConstants.WINDOWS_TOKEN, "ntlm_token");

        Map<String, String> blankTokenMap = new HashMap<>();
        blankTokenMap.put(OAuth.OAUTH_GRANT_TYPE, GrantType.IWA_NTLM.toString());
        blankTokenMap.put(OAuthConstants.WINDOWS_TOKEN, StringUtils.EMPTY);
        Map<String, String> nullTokenMap = new HashMap<>();
        nullTokenMap.put(OAuth.OAUTH_GRANT_TYPE, GrantType.IWA_NTLM.toString());
        nullTokenMap.put(OAuthConstants.WINDOWS_TOKEN, null);

        return new Object[][]{
                {allParamPresentMap, true},
                {blankGrantTypeMap, false},
                {nullGrantTypeMap, false},
                {blankTokenMap, false},
                {nullTokenMap, false}
        };
    }

    @Test(dataProvider = "Request Provider")
    public void testValidateRequiredParameters(Map<String, String> headerMap, boolean shouldPass) throws Exception {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        for (Map.Entry<String, String> entry : headerMap.entrySet()) {
            when(mockRequest.getParameter(entry.getKey())).thenReturn(entry.getValue());
        }
        if (shouldPass) {
            testedValidator.validateRequiredParameters(mockRequest);
            // Nothing to assert here. The above method will only throw an exception if not valid
        } else {
            try {
                testedValidator.validateRequiredParameters(mockRequest);
                fail("Request validation should have failed");
            } catch (OAuthProblemException e) {
                assertTrue(e.getMessage().startsWith(OAuthError.TokenResponse.INVALID_REQUEST), "Invalid error " +
                        "message received. Received was: " + e.getMessage());
            }
        }
    }
}
