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
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.oauth.ciba.common.CibaParams;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.dto.AuthzRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthResponseDTO;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.exceptions.ErrorCodes;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.ciba.util.CibaAuthUtil;
import org.wso2.carbon.identity.oauth.endpoint.exception.CibaAuthFailedException;
import org.wso2.carbon.identity.oauth.endpoint.util.TestOAuthEndpointBase;

import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


@PrepareForTest({CibaParams.class, CibaDAOFactory.class, AuthzRequestDTO.class, CibaAuthRequestDTO.class,
        CibaAuthResponseDTO.class, CibaCoreException.class, ErrorCodes.class, CibaAuthCodeDO.class, CibaAuthUtil.class,
        CibaAuthFailedException.class, JWT.class,})
public class OAuth2CibaEndpointTest extends TestOAuthEndpointBase {

    @Mock
    HttpServletRequest httpServletRequest;

    @Mock
    HttpServletResponse httpServletResponse;

    @Mock
    CibaAuthRequestDTO cibaAuthRequestDTO;

    @Mock
    CibaAuthFailedException cibaAuthFailedException;

    @Mock
    CibaAuthResponseDTO cibaAuthResponseDTO;

    @Mock
    AuthzRequestDTO authzRequestDTO;

    private static final String request = "eyJhbGciOiJIUzUxMiJ9" +
            ".eyJpc3MiOiJaenhtRHFxSzhZWWZqdGxPaDl2dzg1cW5OVm9hIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9vYXV0aDIvY2liYSIsImJpbmRpbmdfbWVzc2FnZSI6IjE5MDgxOTk1IiwibG9naW5faGludCI6InZpdmVrIiwic2NvcGUiOiJvcGVuaWQgc21zIiwiaWF0IjoxNTczMDk5NDEzLCJleHAiOjE1NzMxNDQzNzEsIm5iZiI6MTU3MzA5OTQxMywianRpIjoiOWZmODQ1YjktMjBiZi00MDMzLTllZDMtM2NjYzYzZjUyMDRjIiwicmVxdWVzdGVkX2V4cGlyeSI6MzcwMH0.dcyX4dNaI-u0maButJ4h3q383OnDXCPMzgHzpU3ZHxsjlGIC_I-B_3QApMnQCav8-cSaYv62FWTqoUOF9wf4yw";


   private static final String REQUEST_ATTRIBUTE = "request";
    private OAuth2CibaEndpoint oAuth2CibaEndpoint;
    private Object oauth2CibaEndpontObject;

    @BeforeTest
    public void setUp() throws Exception {

        System.setProperty(
                CarbonBaseConstants.CARBON_HOME,
                Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString()
                          );
        oAuth2CibaEndpoint = new OAuth2CibaEndpoint();

        Class<?> clazz = OAuth2CibaEndpoint.class;
        oauth2CibaEndpontObject = clazz.newInstance();
    }


    @DataProvider(name = "provideRequestParams")
    public Object[][] provideRequestParams() {

        return new Object[][]{
                {REQUEST_ATTRIBUTE, request, HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE,request+"frsgtg.ftetryyru",HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE,"eftaeg",HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE,"etfcra.cesavr",HttpServletResponse.SC_BAD_REQUEST},
                {REQUEST_ATTRIBUTE,"vrsgyb.waygersh.reygsrab",HttpServletResponse.SC_BAD_REQUEST},
                {"", "", HttpServletResponse.SC_BAD_REQUEST},
        };

    }

    @Test(dataProvider = "provideRequestParams")
    public void testCiba(String parameter, String paramValue, int expectedStatus){

        Assert.assertEquals(HttpServletResponse.SC_BAD_REQUEST,expectedStatus);
    }
}