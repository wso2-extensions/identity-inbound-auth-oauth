package org.wso2.carbon.identity.oauth2.responsemode.provider;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.responsemode.provider.impl.FragmentResponseModeProvider;
import org.wso2.carbon.identity.oauth2.responsemode.provider.impl.QueryResponseModeProvider;

import java.util.Arrays;
import java.util.HashSet;

public class ResponseModeProviderTest {

    @DataProvider(name = "fragmentDataProvider")
    private Object[][] fragmentDataProvider() {

        return new Object[][] {
                // AuthorizationResponseDTO, provided callback url, expected redirect url
                {getAuthResponseDTO("https://www.google.com/redirects/redirect1", "code1", null,
                        null),
                        "https://www.google.com/redirects/redirect1",
                        "https://www.google.com/redirects/redirect1#code=code1"},
                {getAuthResponseDTO("https://www.google.com/redirects/redirect2?param1=abc&param2=xyz",
                        "code2", null, null),
                        "https://www.google.com/redirects/redirect2?param1=abc&param2=xyz",
                        "https://www.google.com/redirects/redirect2?param1=abc&param2=xyz#code=code2"},
                {getAuthResponseDTO("https://www.google.com/redirects/redirect2?param1=abc&param2=xyz",
                        "code3", "access_token_1", null),
                        "https://www.google.com/redirects/redirect2?param1=abc&param2=xyz",
                        "https://www.google.com/redirects/redirect2?param1=abc&param2=xyz#access_token=access_token_1" +
                                "&expires_in=3600&code=code3&scope=randomScope"},
                {getAuthResponseDTO("https://www.google.com/redirects/redirect2?param1=abc&param2=xyz",
                        null, null, "subject_token_1"),
                        "https://www.google.com/redirects/redirect2?param1=abc&param2=xyz",
                        "https://www.google.com/redirects/redirect2?param1=abc&param2=xyz#" +
                                "subject_token=subject_token_1"},

        };
    }

    @Test(dataProvider = "fragmentDataProvider", description = "Test whether the redirect url generated " +
            "by the FragmentResponseModeProvider is correct.")
    public void testFragmentRedirectUrl(AuthorizationResponseDTO authorizationResponseDTO, String callbackUrl,
                                String expectedRedirectUrl) {

        FragmentResponseModeProvider fragmentResponseModeProvider = new FragmentResponseModeProvider();
        String redirectUrl = fragmentResponseModeProvider.getAuthResponseRedirectUrl(authorizationResponseDTO);

        Assert.assertTrue(redirectUrl.contains(callbackUrl), "Redirect url does not " +
                "contain the callback url provided.");
        Assert.assertTrue(redirectUrl.contains("#"), "Redirect url does not contain a fragment part.");
        if (authorizationResponseDTO.getSuccessResponseDTO().getAuthorizationCode() != null) {
            Assert.assertTrue(redirectUrl.contains("code="),
                    "Redirect url does not contain the authorization code.");
        }
        Assert.assertEquals(redirectUrl, expectedRedirectUrl, "Redirect url is not as expected.");
    }

    @DataProvider(name = "queryDataProvider")
    private Object[][] queryDataProvider() {

        return new Object[][] {
                // AuthorizationResponseDTO, provided callback url, expected redirect url
                {getAuthResponseDTO("https://www.google.com/redirects/redirect1", "code1", null,
                        null),
                        "https://www.google.com/redirects/redirect1",
                        "https://www.google.com/redirects/redirect1?code=code1"},
                {getAuthResponseDTO("https://www.google.com/redirects/redirect2?param1=abc&param2=xyz",
                        "code2", null, null),
                        "https://www.google.com/redirects/redirect2?param1=abc&param2=xyz",
                        "https://www.google.com/redirects/redirect2?param1=abc&param2=xyz&code=code2"},
                {getAuthResponseDTO("https://www.google.com/redirects/redirect2?param1=abc&param2=xyz",
                        "code3", "access_token_1", null),
                        "https://www.google.com/redirects/redirect2?param1=abc&param2=xyz",
                        "https://www.google.com/redirects/redirect2?param1=abc&param2=xyz&access_token=access_token_1" +
                                "&expires_in=3600&code=code3&scope=randomScope"},
                {getAuthResponseDTO("https://www.google.com/redirects/redirect2?param1=abc&param2=xyz",
                        null, null, "subject_token_1"),
                        "https://www.google.com/redirects/redirect2?param1=abc&param2=xyz",
                        "https://www.google.com/redirects/redirect2?param1=abc&param2=xyz" +
                                "&subject_token=subject_token_1"},

        };
    }

    @Test(dataProvider = "queryDataProvider", description = "Test whether the redirect url generated " +
            "by the QueryResponseModeProvider is correct.")
    public void testQueryRedirectUrl(AuthorizationResponseDTO authorizationResponseDTO, String callbackUrl,
                                        String expectedRedirectUrl) {

        QueryResponseModeProvider queryResponseModeProvider = new QueryResponseModeProvider();
        String redirectUrl = queryResponseModeProvider.getAuthResponseRedirectUrl(authorizationResponseDTO);

        Assert.assertTrue(redirectUrl.contains(callbackUrl), "Redirect url does not " +
                "contain the callback url provided.");
        Assert.assertTrue(redirectUrl.contains("?"), "Redirect url does not contain a query part.");
        if (authorizationResponseDTO.getSuccessResponseDTO().getAuthorizationCode() != null) {
            Assert.assertTrue(redirectUrl.contains("code="),
                    "Redirect url does not contain the authorization code.");
        }
        Assert.assertEquals(redirectUrl, expectedRedirectUrl, "Redirect url is not as expected.");
    }

    /**
     * This method creates and returns dummy AuthorizationResponseDTO instance.
     * @return AuthorizationResponseDTO DTO
     */
    private AuthorizationResponseDTO getAuthResponseDTO(String redirectURI, String code, String accessToken,
                                                        String subjectToken) {

        AuthorizationResponseDTO authorizationResponseDTO = new AuthorizationResponseDTO();
        authorizationResponseDTO.setRedirectUrl(redirectURI);

        authorizationResponseDTO.getSuccessResponseDTO().setAuthorizationCode(code);
        authorizationResponseDTO.getSuccessResponseDTO().setSubjectToken(subjectToken);
        authorizationResponseDTO.getSuccessResponseDTO().setAccessToken(accessToken);
        if (accessToken != null) {
            authorizationResponseDTO.getSuccessResponseDTO().setScope(new HashSet<>(Arrays.asList("randomScope")));
            authorizationResponseDTO.getSuccessResponseDTO().setValidityPeriod(3600);
        }

        return authorizationResponseDTO;
    }
}
