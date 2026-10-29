/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth2.cimd;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.net.InetAddress;

import static org.testng.Assert.assertEquals;

public class SpecialUseAddressesTest {

    @DataProvider
    public Object[][] addresses() {

        return new Object[][]{
                {"127.0.0.1", true},
                {"10.1.2.3", true},
                {"172.16.0.1", true},
                {"172.31.255.255", true},
                {"192.168.1.1", true},
                {"169.254.169.254", true},
                {"100.64.0.1", true},
                {"0.0.0.0", true},
                {"198.18.0.1", true},
                {"224.0.0.1", true},
                {"255.255.255.255", true},
                {"::1", true},
                {"::", true},
                {"fe80::1", true},
                {"fd00::1", true},
                {"::ffff:10.0.0.1", true},
                {"64:ff9b::a00:1", true},
                {"2001:db8::1", true},
                {"::7f00:1", true},
                {"::ffff:0:a00:1", true},
                {"168.63.129.16", true},
                {"8.8.8.8", false},
                {"172.32.0.1", false},
                {"100.128.0.1", false},
                {"160.79.104.10", false},
                {"2606:4700::1111", false},
        };
    }

    @Test(dataProvider = "addresses")
    public void testIsSpecialUse(String address, boolean expected) throws Exception {

        assertEquals(SpecialUseAddresses.isSpecialUse(InetAddress.getByName(address)), expected, address);
    }
}
