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

package org.wso2.carbon.identity.oauth2.validators;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;

import static org.testng.Assert.assertEquals;

public class OAuth2TokenValidationMessageContextTest {

    private OAuth2TokenValidationMessageContext oAuth2TokenValidationMessageContext;
    private OAuth2TokenValidationRequestDTO requestDTO;
    private OAuth2TokenValidationResponseDTO responseDTO;

    @BeforeMethod
    public void setUp() throws Exception {
        requestDTO = new OAuth2TokenValidationRequestDTO();
        responseDTO = new OAuth2TokenValidationResponseDTO();
        oAuth2TokenValidationMessageContext = new OAuth2TokenValidationMessageContext(requestDTO, responseDTO);
    }

    @Test
    public void testGetRequestDTO() throws Exception {
        assertEquals(oAuth2TokenValidationMessageContext.getRequestDTO(), requestDTO);
    }

    @Test
    public void testGetResponseDTO() throws Exception {
        assertEquals(oAuth2TokenValidationMessageContext.getResponseDTO(), responseDTO);
    }

    @Test
    public void testAddProperty() throws Exception {
        oAuth2TokenValidationMessageContext.addProperty("testProperty", "testValue");
        assertEquals(oAuth2TokenValidationMessageContext.getProperty("testProperty"), "testValue");
    }

    @Test
    public void testGetProperty() throws Exception {
        oAuth2TokenValidationMessageContext.addProperty("testProperty", "testValue");
        assertEquals(oAuth2TokenValidationMessageContext.getProperty("testProperty"), "testValue");
    }

}
