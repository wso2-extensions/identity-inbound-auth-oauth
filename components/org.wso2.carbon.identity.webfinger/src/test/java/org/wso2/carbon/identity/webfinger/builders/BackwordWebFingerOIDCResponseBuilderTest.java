/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.webfinger.builders;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.webfinger.WebFingerEndpointException;
import org.wso2.carbon.identity.webfinger.WebFingerRequest;
import org.wso2.carbon.identity.webfinger.WebFingerResponse;

import java.net.URISyntaxException;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;

@PrepareForTest({OAuth2Util.OAuthURL.class})
/**
 * Unit test coverage for WebFingerOIDCResponseBuilder class
 */
public class BackwordWebFingerOIDCResponseBuilderTest extends PowerMockTestCase {

    private WebFingerOIDCResponseBuilder webFingerOIDCResponseBuilder;
    private WebFingerRequest webFingerRequest;
    private final String oidcDiscoveryUrl = "https://oidc.testdomain.wso2.org:9443/oauth2/oidcdiscovery";
    private final String rel = "http://openid.net/specs/connect/1.0/issuer";
    private final String resource = "https://oidc.testdomain.wso2.org:9443/.well-known/webfinger";
    private final String host = "oidc.testdomain.wso2.org";
    private final String tenant = "carbon.super";
    private final String path = "/.well-known/webfinger";
    private final String scheme = "https";
    private final int port = 9443;

    @Mock
    OAuth2Util.OAuthURL oAuthURL;

    @BeforeMethod
    public void setUp() throws Exception {
        webFingerOIDCResponseBuilder = new WebFingerOIDCResponseBuilder();
        webFingerRequest = new WebFingerRequest();

        webFingerRequest.setResource(resource);
        webFingerRequest.setHost(host);
        webFingerRequest.setScheme(scheme);
        webFingerRequest.setPort(port);
        webFingerRequest.setRel(rel);
        webFingerRequest.setTenant(tenant);

        mockStatic(OAuth2Util.OAuthURL.class);
    }

    @Test
    public void testBuildWebFingerResponse() throws Exception {
        when(OAuth2Util.OAuthURL.getOidcDiscoveryEPUrl(any(String.class))).thenReturn(oidcDiscoveryUrl);
        WebFingerResponse webFingerResponse = webFingerOIDCResponseBuilder.buildWebFingerResponse(webFingerRequest);
        assertEquals(webFingerResponse.getLinks().get(0).getRel(), rel, "rel is properly assigned");
        assertEquals(webFingerResponse.getLinks().get(0).getHref(), oidcDiscoveryUrl, "href is properly assigned");
        assertEquals(webFingerResponse.getSubject(), webFingerRequest.getResource(), "subject is properly assigned");
    }

    @Test(expectedExceptions = ServerConfigurationException.class)
    public void testBuildWebFingerException() throws URISyntaxException, WebFingerEndpointException,
            ServerConfigurationException {
        when(OAuth2Util.OAuthURL.getOidcDiscoveryEPUrl(anyString())).thenThrow
                (new URISyntaxException("Error", "Exception"));
        try {
            webFingerOIDCResponseBuilder.buildWebFingerResponse(webFingerRequest);
        } catch (ServerConfigurationException e) {
            throw e;
        }
    }
}
