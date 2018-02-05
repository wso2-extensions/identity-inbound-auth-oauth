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
package org.wso2.carbon.identity.oauth.dcr.util;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.oauth.dcr.context.DCRMessageContext;
import org.wso2.carbon.identity.oauth.dcr.handler.RegistrationHandler;
import org.wso2.carbon.identity.oauth.dcr.handler.UnRegistrationHandler;
import org.wso2.carbon.identity.oauth.dcr.internal.DCRDataHolder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest(DCRDataHolder.class)
public class HandlerManagerTest {
    @Mock
    private DCRDataHolder dataHolder;

    @DataProvider(name = "BuildRegistrationHandlers")
    public Object[][] buildRegistrationHandlers() {
        Map<String,String> param = new HashMap<String, String>();
        param.put("client_id","N2QqQluzQuL5X6CtM3KZwqzLQhUa");
        param.put("client_secret","4AXWrN88aEfMvq2h_G0dN05KRsUa");
        DCRMessageContext dcrMessageContext = new DCRMessageContext(param);
        RegistrationHandler registrationHandler1 = new RegistrationHandler();
        RegistrationHandler registrationHandler2 = new RegistrationHandler();
        List<RegistrationHandler> registrationHandlers1 = new ArrayList<>();
        registrationHandlers1.add(registrationHandler1);
        registrationHandlers1.add(registrationHandler2);
        List<RegistrationHandler> registrationHandlers2 = new ArrayList<>();
        registrationHandlers2.add(registrationHandler1);
        List<RegistrationHandler> registrationHandlers3 = new ArrayList<>();
        return new Object[][] {
                {dcrMessageContext, null},
                {dcrMessageContext, registrationHandlers1},
                {dcrMessageContext, registrationHandlers2},
                {dcrMessageContext, registrationHandlers3}
        };
    }

    @Test(dataProvider = "BuildRegistrationHandlers")
    public void testGetRegistrationHandler(Object dcrMessageContext, Object handlers)  {
        mockStatic(DCRDataHolder.class);
        when(DCRDataHolder.getInstance()).thenReturn(dataHolder);
        when(dataHolder.getRegistrationHandlerList()).thenReturn((List<RegistrationHandler>) handlers);
        try {
            Assert.assertNotNull(HandlerManager.getInstance()
                    .getRegistrationHandler((DCRMessageContext) dcrMessageContext));
        } catch (IdentityRuntimeException e) {
            Assert.assertEquals(e.getMessage(),"Cannot find AuthenticationHandler to handle this request");
        }
    }

    @DataProvider(name = "BuildUnRegistrationHandlers")
    public Object[][] buildUnRegistrationHandlers() {
        Map<String,String> param = new HashMap<String, String>();
        param.put("client_id","N2QqQluzQuL5X6CtM3KZwqzLQhUa");
        param.put("client_secret","4AXWrN88aEfMvq2h_G0dN05KRsUa");
        DCRMessageContext dcrMessageContext = new DCRMessageContext(param);
        UnRegistrationHandler unRegistrationHandler1 = new UnRegistrationHandler();
        UnRegistrationHandler unRegistrationHandler2 = new UnRegistrationHandler();
        List<UnRegistrationHandler> unRegistrationHandlers1 = new ArrayList<>();
        unRegistrationHandlers1.add(unRegistrationHandler1);
        unRegistrationHandlers1.add(unRegistrationHandler2);
        List<UnRegistrationHandler> unRegistrationHandlers2 = new ArrayList<>();
        unRegistrationHandlers2.add(unRegistrationHandler1);
        List<UnRegistrationHandler> unRegistrationHandlers3 = new ArrayList<>();
        return new Object[][] {
                {dcrMessageContext, null},
                {dcrMessageContext, unRegistrationHandlers1},
                {dcrMessageContext, unRegistrationHandlers2},
                {dcrMessageContext,unRegistrationHandlers3}
        };
    }

    @Test(dataProvider = "BuildUnRegistrationHandlers")
    public void testGetUnRegistrationHandlerException(Object dcrMessageContext, Object handlers){
        mockStatic(DCRDataHolder.class);
        when(DCRDataHolder.getInstance()).thenReturn(dataHolder);
        when(dataHolder.getUnRegistrationHandlerList()).thenReturn((List<UnRegistrationHandler>) handlers);
        try {
            Assert.assertNotNull(HandlerManager.getInstance()
                    .getUnRegistrationHandler((DCRMessageContext) dcrMessageContext));
        } catch (IdentityRuntimeException e) {
            Assert.assertEquals(e.getMessage(),"Cannot find AuthenticationHandler to handle this request");
        }
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}
