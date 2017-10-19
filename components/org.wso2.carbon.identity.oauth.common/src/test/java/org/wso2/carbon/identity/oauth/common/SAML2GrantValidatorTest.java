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
 * Unit tests for SAML2GrantValidator.
 */
public class SAML2GrantValidatorTest {

    private SAML2GrantValidator testedValidator;

    @BeforeMethod
    public void setUp() throws Exception {
        testedValidator = new SAML2GrantValidator();
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    @DataProvider(name = "Request Provider")
    public Object[][] getRequestParams() {
        Map<String, String> allParamPresentMap = new HashMap<>();
        allParamPresentMap.put(OAuth.OAUTH_GRANT_TYPE, GrantType.SAML20_BEARER.toString());
        allParamPresentMap.put(OAuth.OAUTH_ASSERTION, "assertion");
        Map<String, String> blankGrantTypeMap = new HashMap<>();
        blankGrantTypeMap.put(OAuth.OAUTH_GRANT_TYPE, StringUtils.EMPTY);
        blankGrantTypeMap.put(OAuth.OAUTH_ASSERTION, "assertion");
        Map<String, String> blankAssertionMap = new HashMap<>();
        blankAssertionMap.put(OAuth.OAUTH_GRANT_TYPE, GrantType.SAML20_BEARER.toString());
        blankAssertionMap.put(OAuth.OAUTH_ASSERTION, StringUtils.EMPTY);
        return new Object[][]{
                {allParamPresentMap, true},
                {blankGrantTypeMap, false},
                {blankAssertionMap, false}
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
                        "message received");
            }
        }
    }
}
