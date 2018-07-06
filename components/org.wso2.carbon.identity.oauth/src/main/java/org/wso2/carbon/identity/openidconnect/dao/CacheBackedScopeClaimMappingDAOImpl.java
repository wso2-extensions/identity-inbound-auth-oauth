/*
 *
 *   Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.wso2.carbon.identity.openidconnect.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.openidconnect.cache.OIDCScopeClaimCache;
import org.wso2.carbon.identity.openidconnect.cache.OIDCScopeClaimCacheEntry;

import java.util.ArrayList;
import java.util.List;

/**
 * Default cache backed implementation of {@link ScopeClaimMappingDAO}. This handles {@link OIDCScopeClaimCache}
 * related cache layer operations.
 */
public class CacheBackedScopeClaimMappingDAOImpl extends ScopeClaimMappingDAOImpl {

    private final Log log = LogFactory.getLog(CacheBackedScopeClaimMappingDAOImpl.class);
    private OIDCScopeClaimCache oidcScopeClaimCache = OIDCScopeClaimCache.getInstance();
    private ScopeClaimMappingDAO defaultScopeClaimMappingDAO = new ScopeClaimMappingDAOImpl();

    @Override
    public void addScopes(int tenantId, List<ScopeDTO> scopeClaimsMap) throws IdentityOAuth2Exception {

        super.addScopes(tenantId, scopeClaimsMap);
        OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry = new OIDCScopeClaimCacheEntry();
        oidcScopeClaimCacheEntry.setScopeClaimMapping(scopeClaimsMap);
        oidcScopeClaimCache.addScopeClaimMap(tenantId, oidcScopeClaimCacheEntry);
        if (log.isDebugEnabled()) {
            log.debug("The cache oidcScopeClaimCache is cleared for the tenant : " + tenantId);
        }
    }

    public void addScope(int tenantId, String scope, String[] claimsList) throws IdentityOAuth2Exception {

        oidcScopeClaimCache.clearScopeClaimMap(tenantId);
        super.addScope(tenantId, scope, claimsList);
        if (log.isDebugEnabled()) {
            log.debug("The cache oidcScopeClaimCache is cleared for the tenant : " + tenantId);
        }
    }

    @Override
    public List<ScopeDTO> getScopes(int tenantId) throws IdentityOAuth2Exception {

        OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry = oidcScopeClaimCache.getScopeClaimMap(tenantId);
        oidcScopeClaimCacheEntry = loadOIDCScopeClaims(tenantId, oidcScopeClaimCacheEntry);
        return oidcScopeClaimCacheEntry.getScopeClaimMapping();
    }

    @Override
    public void deleteScope(String scope, int tenantId) throws IdentityOAuth2Exception {

        super.deleteScope(scope, tenantId);
        oidcScopeClaimCache.clearScopeClaimMap(tenantId);
        if (log.isDebugEnabled()) {
            log.debug("OIDC scope claims mapping deleted from the oidcScopeClaimCache for tenant: " + tenantId);
        }
    }

    @Override
    public void updateScope(String scope, int tenantId, List<String> addClaims, List<String> deleteClaims)
            throws IdentityOAuth2Exception {

        super.updateScope(scope, tenantId, addClaims, deleteClaims);
        oidcScopeClaimCache.clearScopeClaimMap(tenantId);
        if (log.isDebugEnabled()) {
            log.debug("The cache oidcScopeClaimCache is cleared for the tenant : " + tenantId);
        }
    }

    @Override
    public List<String> getScopeNames(int tenantId) throws IdentityOAuth2Exception {

        OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry = oidcScopeClaimCache.getScopeClaimMap(tenantId);
        oidcScopeClaimCacheEntry = loadOIDCScopeClaims(tenantId, oidcScopeClaimCacheEntry);
        List<String> scopes = new ArrayList<>();
        for (ScopeDTO scopeDTO : oidcScopeClaimCacheEntry.getScopeClaimMapping()) {
            scopes.add(scopeDTO.getName());
        }
        return scopes;
    }

    @Override
    public ScopeDTO getClaims(String scope, int tenantId) throws IdentityOAuth2Exception {

        OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry = oidcScopeClaimCache.getScopeClaimMap(tenantId);
        oidcScopeClaimCacheEntry = loadOIDCScopeClaims(tenantId, oidcScopeClaimCacheEntry);
        ScopeDTO scopeDTO = new ScopeDTO();
        for (ScopeDTO scopeObj : oidcScopeClaimCacheEntry.getScopeClaimMapping()) {
            if (scope.equals(scopeObj.getName()) && scopeObj.getClaim() != null) {
                scopeDTO = scopeObj;
            }
        }
        return scopeDTO;
    }

    private OIDCScopeClaimCacheEntry loadOIDCScopeClaims(int tenantId, OIDCScopeClaimCacheEntry
            oidcScopeClaimCacheEntry) throws IdentityOAuth2Exception {

        if (oidcScopeClaimCacheEntry == null || oidcScopeClaimCacheEntry.getScopeClaimMapping().size() == 0) {
            if (log.isDebugEnabled()) {
                log.debug("Cache miss for OIDC scopes claims mapping for tenant: " + tenantId);
            }
            oidcScopeClaimCacheEntry = new OIDCScopeClaimCacheEntry();
            List<ScopeDTO> scopeClaims = defaultScopeClaimMappingDAO.getScopes(tenantId);

            oidcScopeClaimCacheEntry.setScopeClaimMapping(scopeClaims);
            oidcScopeClaimCache.addScopeClaimMap(tenantId, oidcScopeClaimCacheEntry);
            if (log.isDebugEnabled()) {
                log.debug("OIDC scopes and mapped claims are loaded from the database and inserted to the cache for " +
                        "the tenant : " + tenantId);
            }
        }
        return oidcScopeClaimCacheEntry;
    }
}
