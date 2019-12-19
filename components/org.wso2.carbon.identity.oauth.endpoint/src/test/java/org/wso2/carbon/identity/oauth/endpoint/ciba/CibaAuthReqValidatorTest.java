/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.ciba;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.reflect.internal.WhiteboxImpl;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaClientException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeRequest;
import org.wso2.carbon.identity.oauth.endpoint.util.TestOAuthEndpointBase;

import java.nio.file.Paths;

@PrepareForTest({CibaConstants.class, CibaCoreException.class, ErrorCodes.class, CibaClientException.class, JWT.class})
public class CibaAuthReqValidatorTest extends TestOAuthEndpointBase {

    private static final String request = "eyJhbGciOiJIUzUxMiJ9" +
            ".eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV" +
            "0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6IjE5MDgxOTk1IiwibG9naW5faGludCI6InZpdmVrIiwic2NvcGUiOiJvcGV" +
            "uaWQgc21zIiwiaWF0IjoxNTczMDk5NDEzLCJleHAiOjE1NzMxNDQzNzEsIm5iZiI6MTU3MzA5OTQxMywianRpIjoiOWZmODQ1" +
            "YjktMjBiZi00MDMzLTllZDMtM2NjYzYzZjUyMDRjIiwicmVxdWVzdGVkX2V4cGlyeSI6MzcwMH0.dcyX4dNaI-u0maButJ4h3q" +
            "383OnDXCPMzgHzpU3ZHxsjlGIC_I-B_3QApMnQCav8-cSaYv62FWTqoUOF9wf4yw";

    @Mock
    CibaAuthCodeRequest authCodeRequest;

    @Mock
    CibaAuthRequestValidator cibaAuthRequestValidator;

    @BeforeTest
    public void setUp() throws Exception {

        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
                          );
        Class<?> clazz = CibaAuthRequestValidator.class;
    }

    @DataProvider(name = "provideRequestParams")
    public Object[][] provideRequestParams() {

        return new Object[][]{
                {request + "frsgtg.ftetryyru"},
                {"eftaeg"},
                {"etfcra.cesavr"},
                {"vrsgyb.waygersh.reygsrab"},
                {""},
        };

    }

    @Test(dataProvider = "provideRequestParams", expectedExceptions = {CibaClientException.class,
            java.text.ParseException.class})
    public void testValidateAudience(String request) throws Exception {

        SignedJWT signedJWT = SignedJWT.parse(request);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        WhiteboxImpl.invokeMethod(cibaAuthRequestValidator, "validateAudience", claimsSet, authCodeRequest);
    }
}
