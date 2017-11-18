/*
* Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package org.wso2.carbon.identity.openidconnect;

import org.apache.commons.collections.map.HashedMap;
import org.junit.Assert;
import org.mockito.internal.util.reflection.Whitebox;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.TestConstants;

import java.util.Calendar;
import java.util.Map;

public class RememberMeStoreTest {

    private RememberMeStore rememberMeStore;

    @BeforeTest
    public void setUp(){
        rememberMeStore = RememberMeStore.getInstance();
    }

    @Test
    public void testStore() {
        rememberMeStore.addUserToStore(TestConstants.USER_NAME);
        boolean userInStore = rememberMeStore.isUserInStore(TestConstants.USER_NAME);
        Assert.assertTrue("User is not added to the store", userInStore);
    }

    @Test
    public void testStoreInvalidUser() {
        boolean userInStore = rememberMeStore.isUserInStore("invalid_username");
        Assert.assertFalse("Invalid user cannot exist in the store", userInStore);
    }

    @Test
    public void testStoreTimeOut() {
        long timeInMillis = Calendar.getInstance().getTimeInMillis();
        Map<String, Long> rememberMeMap = new HashedMap();
        rememberMeMap.put(TestConstants.USER_NAME, timeInMillis - 1400000);
        Whitebox.setInternalState(rememberMeStore, "rememberMeMap", rememberMeMap);
        boolean userInStore = rememberMeStore.isUserInStore(TestConstants.USER_NAME);
        Assert.assertFalse("Session is not expired", userInStore);
    }

}
