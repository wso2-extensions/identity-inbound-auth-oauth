/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.oauth.tokenprocessor;

import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.testutil.IdentityBaseTest;

import static org.testng.Assert.assertEquals;

/**
 * Test Class for the PlainTextPersistenceProcessor.
 */
public class PlainTextPersistenceProcessorTest extends IdentityBaseTest {

    private PlainTextPersistenceProcessor testclass = new PlainTextPersistenceProcessor();

    @Test
    public void testGetProcessedClientId() throws IdentityOAuth2Exception {

        assertEquals(testclass.getProcessedClientId("testClientId"), "testClientId");
    }

    @Test
    public void testGetPreprocessedClientId() throws IdentityOAuth2Exception {

        assertEquals(testclass.getPreprocessedClientId("testPreClientId"), "testPreClientId");
    }

    @Test
    public void testGetProcessedClientSecret() throws IdentityOAuth2Exception {

        assertEquals(testclass.getProcessedClientSecret("testClientSecret"), "testClientSecret");
    }

    @Test
    public void testGetPreprocessedClientSecret() throws IdentityOAuth2Exception {

        assertEquals(testclass.getPreprocessedClientSecret("testClientPreSecret"), "testClientPreSecret");
    }

    @Test
    public void testGetProcessedAuthzCode() throws IdentityOAuth2Exception {

        assertEquals(testclass.getProcessedAuthzCode("testAuthzCode"), "testAuthzCode");
    }

    @Test
    public void testGetPreprocessedAuthzCode() throws IdentityOAuth2Exception {

        assertEquals(testclass.getPreprocessedAuthzCode("testPreAuthzCode"), "testPreAuthzCode");
    }

    @Test
    public void testGetProcessedAccessTokenIdentifier() throws IdentityOAuth2Exception {

        assertEquals(testclass.getProcessedAccessTokenIdentifier("testAccessTokenIdentifier"),
                "testAccessTokenIdentifier");
    }

    @Test
    public void testGetPreprocessedAccessTokenIdentifier() throws IdentityOAuth2Exception {

        assertEquals(testclass.getPreprocessedAccessTokenIdentifier("testPreAccessTokenIdentifier"),
                "testPreAccessTokenIdentifier");
    }

    @Test
    public void testGetProcessedRefreshToken() throws IdentityOAuth2Exception {

        assertEquals(testclass.getProcessedRefreshToken("testRefreshToken"), "testRefreshToken");
    }

    @Test
    public void testGetPreprocessedRefreshToken() throws Exception {

        assertEquals(testclass.getPreprocessedRefreshToken("testPreRefreshToken"),
                "testPreRefreshToken");
    }

}
