package org.wso2.carbon.identity.oauth.common;

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
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.NONCE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.SCOPE;

/**
 * Test class for IDTokenResponseValidator.
 */
public class IDTokenResponseValidatorTest {

    private IDTokenResponseValidator testedResponseValidator;

    @BeforeMethod
    public void setUp() throws Exception {
        testedResponseValidator = new IDTokenResponseValidator();
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    @DataProvider(name = "Request Provider")
    public Object[][] getRequestParams() {
        Map<String, String> ValidOIDCScopeMap = new HashMap<>();
        ValidOIDCScopeMap.put(SCOPE, OAuthConstants.Scope.OPENID);
        Map<String, String> nonOIDCScopeMap = new HashMap<>();
        nonOIDCScopeMap.put(SCOPE, "notOpenid");
        Map<String, String> blankScopeMap = new HashMap<>();
        blankScopeMap.put(SCOPE, "");
        return new Object[][]{
                {ValidOIDCScopeMap, true},
                {nonOIDCScopeMap, false},
                {blankScopeMap, false}
        };
    }

    @Test(dataProvider = "Request Provider")
    public void testValidateRequiredParameters(Map<String, String> headerMap, boolean shouldPass) throws Exception {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        for (Map.Entry<String, String> entry : headerMap.entrySet()) {
            when(mockRequest.getParameter(entry.getKey())).thenReturn(entry.getValue());
        }
        when(mockRequest.getParameter("response_type")).thenReturn("code");
        when(mockRequest.getParameter("client_id")).thenReturn("client_id");
        when(mockRequest.getParameter("redirect_uri")).thenReturn("www.oidc.test.com");
        if (shouldPass) {
            testedResponseValidator.validateRequiredParameters(mockRequest);
            // Nothing to assert here. The above method will only throw an exception if not valid
        } else {
            try {
                testedResponseValidator.validateRequiredParameters(mockRequest);
                fail("Request validation should have failed");
            } catch (OAuthProblemException e) {
                assertTrue(e.getMessage().startsWith(OAuthError.TokenResponse.INVALID_REQUEST), "Invalid error " +
                        "message received");
            }
        }
    }

    @DataProvider(name = "Request Method Provider")
    public Object[][] getRequestMethod() {
        return new Object[][]{
                {"GET", true},
                {"POST", true},
                {"HEAD", false},
                {"DELETE", false},
                {"OPTIONS", false},
                {"PUT", false},
                {"", false},
                {null, false}
        };
    }

    @Test(dataProvider = "Request Method Provider")
    public void testValidateMethod(String method, boolean shouldPass) throws Exception {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getMethod()).thenReturn(method);
        if (shouldPass) {
            testedResponseValidator.validateMethod(mockRequest);
            // Nothing to assert here. The above method will only throw an exception if not valid
        } else {
            try {
                testedResponseValidator.validateMethod(mockRequest);
                fail();
            } catch (OAuthProblemException e) {
                assertTrue(e.getMessage().startsWith(OAuthError.TokenResponse.INVALID_REQUEST), "Invalid error " +
                        "message received. Received was: " + e.getMessage());
            }
        }
    }
}
