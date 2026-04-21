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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.cache;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Class-agnostic guardrail test for FST-serialized CacheEntry subclasses.
 * <p>
 * Each row in {@link #cacheEntries()} declares: the target class, the frozen v0 baseline field list
 * (in original declaration order), and the expected number of {@code @Version}-annotated fields.
 * To extend coverage to another cache entry, add one row — no new test class required.
 */
public class CacheEntryVersioningTest {

    private static final List<String> AUTHORIZATION_GRANT_CACHE_ENTRY_V0_BASELINE = Collections.unmodifiableList(
            Arrays.asList(
                    "codeId",
                    "authorizationCode",
                    "tokenId",
                    "userAttributes",
                    "nonceValue",
                    "pkceCodeChallenge",
                    "pkceCodeChallengeMethod",
                    "acrValue",
                    "selectedAcrValue",
                    "amrList",
                    "essentialClaims",
                    "authTime",
                    "maxAge",
                    "requestObject",
                    "hasNonOIDCClaims",
                    "mappedRemoteClaims",
                    "subjectClaim",
                    "tokenBindingValue",
                    "sessionContextIdentifier",
                    "oidcSessionId",
                    "isRequestObjectFlow",
                    "accessTokenExtendedAttributes",
                    "isApiBasedAuthRequest",
                    "impersonator",
                    "federatedTokens",
                    "audiences",
                    "customClaims",
                    "isPreIssueAccessTokenActionsExecuted",
                    "isPreIssueIDTokenActionsExecuted",
                    "preIssueIDTokenActionDTO"
            ));

    @DataProvider(name = "cacheEntries")
    public Object[][] cacheEntries() {

        return new Object[][] {
                {
                        AuthorizationGrantCacheEntry.class,
                        AUTHORIZATION_GRANT_CACHE_ENTRY_V0_BASELINE,
                        1
                }
        };
    }

    @Test(dataProvider = "cacheEntries")
    public void testFieldVersioningContract(Class<?> target, List<String> v0Baseline, int expectedVersionedCount) {

        CacheEntryVersioningAssert.assertFieldVersioning(target, v0Baseline, expectedVersionedCount);
    }

    @Test(dataProvider = "cacheEntries")
    public void testBaselineFieldOrderPreserved(Class<?> target, List<String> v0Baseline,
                                                int expectedVersionedCount) {

        CacheEntryVersioningAssert.assertBaselinePresent(target, v0Baseline);
    }
}
