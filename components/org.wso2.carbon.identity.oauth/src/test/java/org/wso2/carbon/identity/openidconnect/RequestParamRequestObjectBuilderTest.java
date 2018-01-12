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

package org.wso2.carbon.identity.openidconnect;

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.model.OAuth2Parameters;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.model.RequestObject;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({OAuth2Util.class, OAuthServerConfiguration.class})
public class RequestParamRequestObjectBuilderTest extends PowerMockTestCase {

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @DataProvider(name = "TestBuildRequestObjectTest")
    public Object[][] buildRequestObjectData() {
        RequestObjectTest requestObject = new RequestObjectTest();
        return new Object[][]{
                {requestObject.getRequestJson()},
                {requestObject.getEncodeRequestObject()},
                {requestObject.getEncryptedRequestObject()}
        };
    }

    @Test(dataProvider = "TestBuildRequestObjectTest")
    public void buildRequestObjectTest(String requestObject) throws RequestObjectException {
//        RequestObjectTest requestObjectforTests = new RequestObjectTest();
//        RequestObjectBuilder requestObjectBuilder = new RequestParamRequestObjectBuilder();
//        RequestObject requestObjectInstance = new RequestObject();
//        OAuth2Parameters oAuth2Parameters = new OAuth2Parameters();
//        oAuth2Parameters.setTenantDomain("carbon.super");
//
//        OAuthServerConfiguration oauthServerConfigurationMock = mock(OAuthServerConfiguration.class);
//        RequestObjectValidatorImpl requestObjectValidatorImplMock = mock(RequestObjectValidatorImpl.class);
//
//        mockStatic(OAuthServerConfiguration.class);
//        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);
//
//        mockStatic(OAuth2Util.class);
//        when(OAuth2Util.isValidJson(anyString())).thenReturn(true);
//
//        when((oauthServerConfigurationMock.getRequestObjectValidator())).thenReturn(requestObjectValidatorImplMock);
//        when((requestObjectValidatorImplMock.getPayload())).thenReturn(requestObject,requestObjectforTests.
//                getRequestJson());
//        requestObjectBuilder.buildRequestObject(requestObject, oAuth2Parameters, requestObjectInstance);
//        Assert.assertEquals(requestObjectInstance.getClaimsforRequestParameter().size(), 2);

    }
}
