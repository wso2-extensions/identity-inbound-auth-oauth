/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.oauth2.authcontext;

import com.nimbusds.jose.JWSAlgorithm;
import org.powermock.core.classloader.annotations.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

@PrepareForTest({OAuthServerConfiguration.class, OAuth2Util.class})
public class JWTTokenGeneratorTest extends PowerMockTestCase {

    JWTTokenGenerator jwtTokenGenerator;
    private boolean includeClaims = true;
    private boolean enableSigning = true;
    private String consumerDialectURI = "http://wso2.org/claims";
    private String claimsRetrieverImplClass = "org.wso2.carbon.identity.oauth2.authcontext.DefaultClaimsRetriever";
    private String signatureAlgorithm = "SHA256withRSA";
    private boolean useMultiValueSeparatorForAuthContextToken = true;

    @Mock
    private OAuthServerConfiguration mockedOAuthServerConfiguration;

    @BeforeTest
    public void setUp() throws Exception {
        jwtTokenGenerator = new JWTTokenGenerator();
        jwtTokenGenerator = new JWTTokenGenerator(includeClaims, enableSigning);
    }


    @Test
    public void testInit() throws Exception {
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedOAuthServerConfiguration);
        when(mockedOAuthServerConfiguration.getTimeStampSkewInSeconds()).thenReturn((long) 3);

        mockStatic(OAuth2Util.class);
        when(OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(signatureAlgorithm)).thenReturn(JWSAlgorithm.ES256);
        when(mockedOAuthServerConfiguration.getClaimsRetrieverImplClass()).thenReturn(claimsRetrieverImplClass);
        when(mockedOAuthServerConfiguration.getSignatureAlgorithm()).thenReturn(signatureAlgorithm);
        when(mockedOAuthServerConfiguration.isUseMultiValueSeparatorForAuthContextToken()).thenReturn(useMultiValueSeparatorForAuthContextToken);
        when(mockedOAuthServerConfiguration.getConsumerDialectURI()).thenReturn(consumerDialectURI);

        jwtTokenGenerator.init();
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }
}
