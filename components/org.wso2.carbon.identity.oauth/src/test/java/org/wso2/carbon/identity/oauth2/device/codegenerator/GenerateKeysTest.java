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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.device.codegenerator;

import org.apache.commons.lang.StringUtils;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;

import java.util.Random;

public class GenerateKeysTest extends PowerMockTestCase {

    private static final int NUMBER_OF_KEYS_GENERATED = 10;
    private static final int MIN_KEY_LENGTH = 1;
    private static final int MAX_KEY_LENGTH = 10;

    @DataProvider(name = "provideKeyLengths")
    public Object[][] provideKeyLengths() {

        return new Object[][]{{(new Random()).ints(NUMBER_OF_KEYS_GENERATED, MIN_KEY_LENGTH,
                (MAX_KEY_LENGTH + 1)).toArray()}};
    }

    @Test(dataProvider = "provideKeyLengths")
    public void testGetKey(int[] keyLengths) throws Exception {

        // First, test zero length scenario.
        Assert.assertEquals(StringUtils.EMPTY, GenerateKeys.getKey(0));

        for (int keyLength : keyLengths) {
            String generatedKey = GenerateKeys.getKey(keyLength);
            Assert.assertTrue(validateKey(generatedKey, keyLength));
        }
    }

    private boolean validateKey(String generatedKey, int expectedLength) {

        if (generatedKey.length() != expectedLength) {
            return false;
        }
        for (char eachCharacter : generatedKey.toCharArray()) {
            if (!StringUtils.contains(Constants.KEY_SET, eachCharacter)) {
                return false;
            }
        }
        return true;
    }
}

