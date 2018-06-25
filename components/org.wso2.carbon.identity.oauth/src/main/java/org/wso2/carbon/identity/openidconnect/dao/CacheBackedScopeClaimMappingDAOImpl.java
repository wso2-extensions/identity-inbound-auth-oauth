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

import edu.emory.mathcs.backport.java.util.Arrays;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
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
    public void insertAllScopesAndClaims(int tenantId, List<ScopeDTO> scopeClaimsMap) throws IdentityOAuth2Exception {

        oidcScopeClaimCache.clearScopeClaimMap(tenantId);
        super.insertAllScopesAndClaims(tenantId, scopeClaimsMap);
        if (log.isDebugEnabled()) {
            log.debug("The cache oidcScopeClaimCache is cleared for the tenant : " + tenantId);
        }
    }

    @Override
    public List<ScopeDTO> loadScopesClaimsMapping(int tenantId) throws IdentityOAuth2Exception {

        OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry = oidcScopeClaimCache.getScopeClaimMap(tenantId);
        if (oidcScopeClaimCacheEntry == null) {
            if (log.isDebugEnabled()) {
                log.debug("Cache miss for OIDC scopes claims mapping for tenant: " + tenantId);
            }
            oidcScopeClaimCacheEntry = new OIDCScopeClaimCacheEntry();
            oidcScopeClaimCacheEntry.setScopeClaimMapping(defaultScopeClaimMappingDAO.loadScopesClaimsMapping(tenantId));
            oidcScopeClaimCache.addScopeClaimMap(tenantId, oidcScopeClaimCacheEntry);
            if (log.isDebugEnabled()) {
                log.debug("OIDC scopes and mapped claims are loaded from the database and inserted to the cache for " +
                        "the tenant : " + tenantId);
            }
        }
        return oidcScopeClaimCacheEntry.getScopeClaimMapping();
    }

    @Override
    public void deleteScopeAndClaims(String scope, int tenantId) throws IdentityOAuthAdminException {

        oidcScopeClaimCache.clearScopeClaimMap(tenantId);
        super.deleteScopeAndClaims(scope, tenantId);
        if (log.isDebugEnabled()) {
            log.debug("OIDC scope claims mapping deleted from the oidcScopeClaimCache for tenant: " + tenantId);
        }
    }

    @Override
    public void addNewClaimsForScope(String scope, List<String> claims, int tenantId) throws IdentityOAuth2Exception {

        oidcScopeClaimCache.clearScopeClaimMap(tenantId);
        super.addNewClaimsForScope(scope, claims, tenantId);
        if (log.isDebugEnabled()) {
            log.debug("The cache oidcScopeClaimCache is cleared for the tenant : " + tenantId);
        }
    }

    @Override
    public List<String> loadScopes(int tenantId) throws IdentityOAuth2Exception {

        OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry = oidcScopeClaimCache.getScopeClaimMap(tenantId);
        if (oidcScopeClaimCacheEntry == null) {
            if (log.isDebugEnabled()) {
                log.debug("Cache miss for OIDC scopes claims mapping for tenant: " + tenantId);
            }
            oidcScopeClaimCacheEntry = new OIDCScopeClaimCacheEntry();
            oidcScopeClaimCacheEntry.setScopeClaimMapping(defaultScopeClaimMappingDAO.loadScopesClaimsMapping(tenantId));
            oidcScopeClaimCache.addScopeClaimMap(tenantId, oidcScopeClaimCacheEntry);
            if (log.isDebugEnabled()) {
                log.debug("OIDC scopes and mapped claims are loaded from the database and inserted to the cache for " +
                        "the tenant : " + tenantId);
            }
        }
        List<String> scopes = new ArrayList<>();
        for (ScopeDTO scopeDTO : oidcScopeClaimCacheEntry.getScopeClaimMapping()) {
            scopes.add(scopeDTO.getName());
        }
        return scopes;
    }

    @Override
    public List<String> loadClaims(int tenantId, String scope) throws IdentityOAuth2Exception {

        OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry = oidcScopeClaimCache.getScopeClaimMap(tenantId);
        List<String> claimsList = new ArrayList<>();
        if (oidcScopeClaimCacheEntry == null) {
            if (log.isDebugEnabled()) {
                log.debug("Cache miss for OIDC scopes claims mapping for tenant: " + tenantId);
            }
            oidcScopeClaimCacheEntry = new OIDCScopeClaimCacheEntry();
            oidcScopeClaimCacheEntry.setScopeClaimMapping(defaultScopeClaimMappingDAO.loadScopesClaimsMapping(tenantId));
            oidcScopeClaimCache.addScopeClaimMap(tenantId, oidcScopeClaimCacheEntry);
            if (log.isDebugEnabled()) {
                log.debug("OIDC scopes and mapped claims are loaded from the database and inserted to the cache for " +
                        "the tenant : " + tenantId);
            }
        }
        String[] claims = null;
        for (ScopeDTO scopeDTO : oidcScopeClaimCacheEntry.getScopeClaimMapping()) {
            if (scope.equals(scopeDTO.getName())) {
                claims = scopeDTO.getClaim();
            }
        }
        if (ArrayUtils.isNotEmpty(claims)) {
            claimsList = Arrays.asList(claims);
        }
        return claimsList;
    }
}
