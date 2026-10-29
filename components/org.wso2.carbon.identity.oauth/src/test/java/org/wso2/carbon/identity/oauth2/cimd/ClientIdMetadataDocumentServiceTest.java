/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.cimd;

import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.util.Arrays;
import java.util.Collections;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.fail;

public class ClientIdMetadataDocumentServiceTest {

    private static final String CLAUDE = "https://claude.ai/oauth/mcp-oauth-client-metadata";
    private static final String CHATGPT = "https://chatgpt.com/oauth/client.json";
    private static final String VSCODE = "https://vscode.dev/oauth/client-metadata.json";
    private static final String TENANT = "example.com";

    private MockedStatic<IdentityUtil> identityUtil;
    private MockedStatic<IdentityProviderManager> identityProviderManagerStatic;
    private IdentityProviderManager identityProviderManager;
    private ClientIdMetadataDocumentFetcher fetcher;
    private ClientIdMetadataDocumentService service;

    @BeforeMethod
    public void setUp() throws Exception {

        // IdentityUtil is mocked so the application name check uses its default pattern.
        identityUtil = mockStatic(IdentityUtil.class);
        identityProviderManager = mock(IdentityProviderManager.class);
        identityProviderManagerStatic = mockStatic(IdentityProviderManager.class);
        identityProviderManagerStatic.when(IdentityProviderManager::getInstance).thenReturn(identityProviderManager);
        when(identityProviderManager.getResidentIdP(TENANT)).thenReturn(residentIdp("true"));
        fetcher = mock(ClientIdMetadataDocumentFetcher.class);
        service = new ClientIdMetadataDocumentService(fetcher);
    }

    @AfterMethod
    public void tearDown() {

        identityUtil.close();
        identityProviderManagerStatic.close();
    }

    @Test
    public void testPreviewPublicClient() throws Exception {

        when(fetcher.fetch(CLAUDE)).thenReturn("{\"client_id\":\"" + CLAUDE + "\",\"client_name\":\"Claude\"," +
                "\"client_uri\":\"https://claude.ai\"," +
                "\"redirect_uris\":[\"https://claude.ai/api/mcp/auth_callback\"]," +
                "\"grant_types\":[\"authorization_code\",\"refresh_token\"],\"response_types\":[\"code\"]," +
                "\"token_endpoint_auth_method\":\"none\"}");

        ClientIdMetadataDocument document = service.preview(CLAUDE, TENANT);

        assertEquals(document.getClientId(), CLAUDE);
        assertEquals(document.getClientName(), "Claude");
        assertEquals(document.getClientUri(), "https://claude.ai");
        assertEquals(document.getRedirectUris(),
                Collections.singletonList("https://claude.ai/api/mcp/auth_callback"));
        assertEquals(document.getTokenEndpointAuthMethod(), "none");
        assertNull(document.getJwksUri());
        assertEquals(document.getGrantTypes(), Arrays.asList("authorization_code", "refresh_token"));
    }

    @Test
    public void testPreviewPrivateKeyJwtClient() throws Exception {

        when(fetcher.fetch(CHATGPT)).thenReturn("{\"client_id\":\"" + CHATGPT + "\",\"client_name\":\"ChatGPT\"," +
                "\"redirect_uris\":[\"https://chatgpt.com/connector_platform_oauth_redirect\"]," +
                "\"grant_types\":[\"authorization_code\",\"refresh_token\"]," +
                "\"token_endpoint_auth_method\":\"private_key_jwt\"," +
                "\"jwks_uri\":\"https://chatgpt.com/oauth/jwks.json\"}");

        ClientIdMetadataDocument document = service.preview(CHATGPT, TENANT);

        assertEquals(document.getTokenEndpointAuthMethod(), "private_key_jwt");
        assertEquals(document.getJwksUri(), "https://chatgpt.com/oauth/jwks.json");
    }

    @Test
    public void testPreviewLoopbackRedirectAndNarrowedGrants() throws Exception {

        when(fetcher.fetch(VSCODE)).thenReturn("{\"client_id\":\"" + VSCODE + "\"," +
                "\"redirect_uris\":[\"http://127.0.0.1:33418/\",\"https://vscode.dev/redirect\"]," +
                "\"grant_types\":[\"authorization_code\",\"refresh_token\"," +
                "\"urn:ietf:params:oauth:grant-type:device_code\"],\"token_endpoint_auth_method\":\"none\"}");

        ClientIdMetadataDocument document = service.preview(VSCODE, TENANT);

        assertEquals(document.getClientName(), "vscode.dev");
        assertEquals(document.getGrantTypes(), Arrays.asList("authorization_code", "refresh_token"));
        assertEquals(document.getRedirectUris(), Arrays.asList("http://127.0.0.1:33418/",
                "https://vscode.dev/redirect"));
    }

    @Test
    public void testPreviewDefaultsGrantToAuthorizationCode() throws Exception {

        when(fetcher.fetch(CLAUDE)).thenReturn(document("\"redirect_uris\":[\"https://claude.ai/cb\"]," +
                "\"token_endpoint_auth_method\":\"none\""));

        assertEquals(service.preview(CLAUDE, TENANT).getGrantTypes(), Collections.singletonList("authorization_code"));
    }

    @Test
    public void testPreviewFallsBackToHostForUnusableClientName() throws Exception {

        when(fetcher.fetch(CLAUDE)).thenReturn(document("\"client_name\":\"Claude (Beta)\"," +
                "\"redirect_uris\":[\"https://claude.ai/cb\"],\"token_endpoint_auth_method\":\"none\""));

        assertEquals(service.preview(CLAUDE, TENANT).getClientName(), "claude.ai");
    }

    @Test
    public void testPreviewRejectedWhenDisabled() throws Exception {

        when(identityProviderManager.getResidentIdP(TENANT)).thenReturn(residentIdp("false"));

        assertRejected(CLAUDE, "CIMD-60007");
        verify(fetcher, never()).fetch(anyString());
    }

    @Test
    public void testPreviewRejectedWhenTenantHasNoSetting() throws Exception {

        when(identityProviderManager.getResidentIdP(TENANT)).thenReturn(residentIdp(null));

        assertRejected(CLAUDE, "CIMD-60007");
        verify(fetcher, never()).fetch(anyString());
    }

    @DataProvider
    public Object[][] invalidUrls() {

        StringBuilder longUrl = new StringBuilder("https://example.com/");
        while (longUrl.length() <= ClientIdMetadataDocumentService.MAX_CLIENT_ID_LENGTH) {
            longUrl.append('a');
        }
        return new Object[][]{
                {"http://example.com/client.json", "CIMD-60001"},
                {"https://127.0.0.1/client.json", "CIMD-60001"},
                {"https://[::1]/client.json", "CIMD-60001"},
                {"https://example.com", "CIMD-60001"},
                {"https://example.com/client.json?x=1", "CIMD-60001"},
                {"https://example.com/client.json#x", "CIMD-60001"},
                {"https://user@example.com/client.json", "CIMD-60001"},
                {"https://example.com/a/../client.json", "CIMD-60001"},
                {"https://example.com/a/%2e%2e/client.json", "CIMD-60001"},
                {"https://example.com:8443/client.json", "CIMD-60001"},
                {"not a url", "CIMD-60001"},
                {"", "CIMD-60001"},
                {longUrl.toString(), "CIMD-60006"},
        };
    }

    @Test(dataProvider = "invalidUrls")
    public void testPreviewRejectsInvalidUrlWithoutFetching(String url, String code) throws Exception {

        assertRejected(url, code);
        verify(fetcher, never()).fetch(anyString());
    }

    @DataProvider
    public Object[][] notMatchingResponses() {

        return new Object[][]{
                {"<html>metadata</html>"},
                {"null"},
                {"[1,2]"},
                {"{\"Code\":\"Success\",\"AccessKeyId\":\"secret\"}"},
                {"{\"client_id\":\"https://claude.ai/other\",\"redirect_uris\":[\"https://claude.ai/cb\"]}"},
        };
    }

    @Test(dataProvider = "notMatchingResponses")
    public void testPreviewRejectsResponseThatIsNotTheDocument(String body) throws Exception {

        when(fetcher.fetch(CLAUDE)).thenReturn(body);

        assertRejected(CLAUDE, "CIMD-60002");
    }

    @DataProvider
    public Object[][] ruleViolations() {

        return new Object[][]{
                {"\"redirect_uris\":[],\"token_endpoint_auth_method\":\"none\"", "CIMD-60003"},
                {"\"redirect_uris\":[\"https://evil.example/cb\"],\"token_endpoint_auth_method\":\"none\"",
                        "CIMD-60003"},
                {"\"redirect_uris\":[\"https://claude.ai:8443/cb\"],\"token_endpoint_auth_method\":\"none\"",
                        "CIMD-60003"},
                {"\"redirect_uris\":[\"http://localhost:3000/cb\"],\"token_endpoint_auth_method\":\"none\"",
                        "CIMD-60003"},
                {"\"redirect_uris\":[\"http://claude.ai/cb\"],\"token_endpoint_auth_method\":\"none\"",
                        "CIMD-60003"},
                {"\"redirect_uris\":[\"https://claude.ai/cb\",\"http://[::1]:3000/cb\"]," +
                        "\"token_endpoint_auth_method\":\"none\"", "CIMD-60003"},
                {"\"redirect_uris\":[\"https://claude.ai/cb\"]", "CIMD-60004"},
                {"\"redirect_uris\":[\"https://claude.ai/cb\"],\"token_endpoint_auth_method\":\"client_secret_basic\"",
                        "CIMD-60004"},
                {"\"redirect_uris\":[\"https://claude.ai/cb\"],\"token_endpoint_auth_method\":\"none\"," +
                        "\"client_secret\":\"s\"", "CIMD-60004"},
                {"\"redirect_uris\":[\"https://claude.ai/cb\"],\"token_endpoint_auth_method\":\"private_key_jwt\"",
                        "CIMD-60004"},
                {"\"redirect_uris\":[\"https://claude.ai/cb\"],\"token_endpoint_auth_method\":\"private_key_jwt\"," +
                        "\"jwks\":{\"keys\":[]}", "CIMD-60004"},
                {"\"redirect_uris\":[\"https://claude.ai/cb\"],\"token_endpoint_auth_method\":\"private_key_jwt\"," +
                        "\"jwks_uri\":\"https://10.0.0.1/jwks\"", "CIMD-60004"},
                {"\"redirect_uris\":[\"https://claude.ai/cb\"],\"token_endpoint_auth_method\":\"private_key_jwt\"," +
                        "\"jwks_uri\":\"https://internal.example.com/jwks\"", "CIMD-60004"},
                {"\"redirect_uris\":[\"https://claude.ai/cb\"],\"token_endpoint_auth_method\":\"private_key_jwt\"," +
                        "\"jwks_uri\":\"https://keys.claude.ai/jwks\"", "CIMD-60004"},
                {"\"redirect_uris\":[\"https://claude.ai/cb\"],\"token_endpoint_auth_method\":\"private_key_jwt\"," +
                        "\"jwks_uri\":\"https://claude.ai:8443/jwks\"", "CIMD-60004"},
                {"\"redirect_uris\":[\"https://claude.ai/cb\"],\"token_endpoint_auth_method\":\"none\"," +
                        "\"grant_types\":[\"client_credentials\"]", "CIMD-60005"},
        };
    }

    @Test(dataProvider = "ruleViolations")
    public void testPreviewRejectsRuleViolation(String fields, String code) throws Exception {

        when(fetcher.fetch(CLAUDE)).thenReturn(document(fields));

        assertRejected(CLAUDE, code);
    }

    @Test
    public void testPreviewRejectsCallbackLongerThanStorage() throws Exception {

        StringBuilder redirectUris = new StringBuilder();
        for (int i = 0; i < 60; i++) {
            redirectUris.append(i == 0 ? "" : ",").append("\"https://claude.ai/callback/path/number/").append(i)
                    .append("\"");
        }
        when(fetcher.fetch(CLAUDE)).thenReturn(document("\"redirect_uris\":[" + redirectUris +
                "],\"token_endpoint_auth_method\":\"none\""));

        assertRejected(CLAUDE, "CIMD-60006");
    }

    @Test
    public void testBuildCallbackUrl() {

        assertEquals(ClientIdMetadataDocumentService.buildCallbackUrl(
                Collections.singletonList("https://claude.ai/cb")), "https://claude.ai/cb");
        assertEquals(ClientIdMetadataDocumentService.buildCallbackUrl(
                        Arrays.asList("http://127.0.0.1:33418/", "https://vscode.dev/redirect")),
                "regexp=(http://127.0.0.1:33418/|https://vscode\\.dev/redirect)");
        // Characters after the loopback prefix are escaped, so a redirect URI cannot add regex syntax.
        assertEquals(ClientIdMetadataDocumentService.buildCallbackUrl(
                        Arrays.asList("https://claude.ai/cb", "http://127.0.0.1/x)?(.*")),
                "regexp=(https://claude\\.ai/cb|http://127.0.0.1/x\\)\\?\\(\\.\\*)");
    }

    private void assertRejected(String url, String code) {

        try {
            service.preview(url, TENANT);
            fail("Expected the preview to be rejected: " + url);
        } catch (ClientIdMetadataDocumentException e) {
            assertEquals(e.getErrorMessage().getCode(), code, url);
        }
    }

    private static String document(String fields) {

        return "{\"client_id\":\"" + CLAUDE + "\"," + fields + "}";
    }

    private static IdentityProvider residentIdp(String setting) {

        FederatedAuthenticatorConfig oidcConfig = new FederatedAuthenticatorConfig();
        oidcConfig.setName(IdentityApplicationConstants.Authenticator.OIDC.NAME);
        if (setting != null) {
            Property property = new Property();
            property.setName(ClientIdMetadataDocumentService.TENANT_SETTING);
            property.setValue(setting);
            oidcConfig.setProperties(new Property[]{property});
        }
        IdentityProvider residentIdp = new IdentityProvider();
        residentIdp.setFederatedAuthenticatorConfigs(new FederatedAuthenticatorConfig[]{oidcConfig});
        return residentIdp;
    }
}
