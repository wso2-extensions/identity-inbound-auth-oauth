/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.oauth2;

import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TENANT_NAME_FROM_CONTEXT;

/**
 * Test util class for OAuth.
 */
public class TestUtil {

    /**
     * Retrieve and mock the realm service in IdentityTenantUtil.
     *
     * @param tenantId      Tenant ID to be used while mocking tenant manager.
     * @param tenantDomain  Tenant domain to be used while mocking tenant manager.
     * @throws UserStoreException If an error occurs.
     */
    public static void mockRealmInIdentityTenantUtil(int tenantId, String tenantDomain) throws UserStoreException {

        RealmService realmService = IdentityTenantUtil.getRealmService();
        RealmService realmServiceMock;
        if (realmService == null) {
            realmServiceMock = mock(RealmService.class);
        } else {
            realmServiceMock = spy(realmService);
        }

        TenantManager tenantManagerMock = mock(TenantManager.class);
        IdentityUtil.threadLocalProperties.get().put(TENANT_NAME_FROM_CONTEXT, tenantDomain);
        when(tenantManagerMock.getTenantId(tenantDomain)).thenReturn(tenantId);
        when(tenantManagerMock.getTenantId(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)).thenReturn(
                MultitenantConstants.SUPER_TENANT_ID);
        when(tenantManagerMock.getDomain(tenantId)).thenReturn(tenantDomain);
        when(tenantManagerMock.getDomain(MultitenantConstants.SUPER_TENANT_ID)).thenReturn(
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        when(realmServiceMock.getTenantManager()).thenReturn(tenantManagerMock);
        IdentityTenantUtil.setRealmService(realmServiceMock);
    }
}
