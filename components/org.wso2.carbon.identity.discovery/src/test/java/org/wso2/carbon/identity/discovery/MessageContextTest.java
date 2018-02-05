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

package org.wso2.carbon.identity.discovery;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

public class MessageContextTest {

    private MessageContext messageContext;
    private OIDProviderRequest oidProviderRequest;

    @Test
    public void testMessageContext() throws Exception {
        try {
            messageContext = new MessageContext(oidProviderRequest);
        } catch (Exception e) {
            fail("Exception occurred while calling the constructor");
        }
    }

    @Test
    public void testSetandGetRequest() throws Exception {
        OIDProviderRequest oidProviderRequest = new OIDProviderRequest();
        messageContext = new MessageContext();
        messageContext.setRequest(oidProviderRequest);
        assertEquals(messageContext.getRequest(), oidProviderRequest, "Error");
    }

    @Test
    public void testSetandGetConfigurations() throws Exception {
        OIDProviderConfigResponse oidProviderConfigResponse = new OIDProviderConfigResponse();
        messageContext = new MessageContext();
        messageContext.setConfigurations(oidProviderConfigResponse);
        assertEquals(messageContext.getConfigurations(), oidProviderConfigResponse, "Error");
    }

}
