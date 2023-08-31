/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.common;

import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.core.classloader.annotations.SuppressStaticInitializationFor;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import javax.servlet.http.HttpServletRequest;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.ALLOWED_CONTENT_TYPES;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.IS_FAPI_CONFORMANT_APP;

/**
 * Test class for OAuthCommonUtil.
 */
@PrepareForTest({OAuth2Util.class})
@SuppressStaticInitializationFor({"org.wso2.carbon.identity.oauth2.util.OAuth2Util"})
public class OAuthCommonUtilTest extends PowerMockTestCase {

    @DataProvider(name = "Content Type Provider")
    public Object[][] getContentType() {

        return new Object[][]{
                {"application/x-www-form-urlencoded", true},
                {"application/json", true},
                {"application/json; charset=utf-8", true},
                {"application/xml", false},
        };
    }

    @Test(dataProvider = "Content Type Provider")
    public void testIsAllowedContentType(String contentType, boolean shouldPass) throws Exception {

        boolean isAllowed = OAuthCommonUtil.isAllowedContentType(contentType, ALLOWED_CONTENT_TYPES);

        if (shouldPass) {
            Assert.assertEquals(isAllowed, true, contentType + " should be an allowed content type");
        } else {
            Assert.assertEquals(isAllowed, false, contentType + " should not be an allowed content type");
        }
    }

    @Test(dataProvider = "Content Type Provider")
    public void testValidateContentTypes(String contentType, boolean shouldPass) throws Exception {

        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getContentType()).thenReturn(contentType);
        try {
            OAuthCommonUtil.validateContentTypes(mockRequest);
            if (!shouldPass) {
                Assert.fail(contentType + " should not be an allowed content type");
            }
        } catch (OAuthProblemException e) {
            if (shouldPass) {
                Assert.fail(contentType + " should be an allowed content type");
            }
        }
    }

    @DataProvider(name = "FAPI status data provider")
    public Object[][] getFapiStatus() {

        return new Object[][]{
                {"true"},
                {"false"}
        };
    }

    @Test(dataProvider = "FAPI status data provider")
    public void testIsFapiConformantApp(String isFapiConformant) throws Exception {

        PowerMockito.mockStatic(OAuth2Util.class);
        ServiceProvider serviceProvider = new ServiceProvider();
        ServiceProviderProperty fapiAppSpProperty = new ServiceProviderProperty();
        fapiAppSpProperty.setName(IS_FAPI_CONFORMANT_APP);
        fapiAppSpProperty.setValue(isFapiConformant);
        serviceProvider.setSpProperties(new ServiceProviderProperty[]{fapiAppSpProperty});
        PowerMockito.when(OAuth2Util.getServiceProvider(Mockito.anyString())).thenReturn(serviceProvider);
        Assert.assertEquals(OAuthCommonUtil.isFapiConformantApp("sample_client_id"), isFapiConformant);

    }
}
