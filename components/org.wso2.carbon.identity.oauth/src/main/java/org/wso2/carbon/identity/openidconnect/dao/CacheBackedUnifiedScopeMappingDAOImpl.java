/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.openidconnect.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.openidconnect.cache.OIDCScopeClaimCacheEntry;
import org.wso2.carbon.identity.openidconnect.cache.UnifiedOIDCScopeClaimCache;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.identity.organization.management.service.util.Utils;

import java.util.ArrayList;
import java.util.List;

/**
 * Cache-backed unified implementation of {@link ScopeClaimMappingDAO}.
 * This handles {@link UnifiedOIDCScopeClaimCache} related cache layer operations.
 */
public class CacheBackedUnifiedScopeMappingDAOImpl extends UnifiedScopeClaimMappingDAOImpl {

    private static final Log log = LogFactory.getLog(CacheBackedUnifiedScopeMappingDAOImpl.class);
    private final UnifiedOIDCScopeClaimCache unifiedOIDCScopeClaimCache = UnifiedOIDCScopeClaimCache.getInstance();
    private final ScopeClaimMappingDAO scopeClaimMappingDAOImpl = new CacheBackedScopeClaimMappingDAOImpl();

    @Override
    public void initScopeClaimMapping(int tenantId, List<ScopeDTO> scopeClaims) throws IdentityOAuth2Exception {

        super.initScopeClaimMapping(tenantId, scopeClaims);
        if (resolveWithHierarchicalMode(tenantId)) {
            OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry = new OIDCScopeClaimCacheEntry();
            oidcScopeClaimCacheEntry.setScopeClaimMapping(scopeClaims);
            unifiedOIDCScopeClaimCache.addScopeClaimMap(tenantId, oidcScopeClaimCacheEntry);
            if (log.isDebugEnabled()) {
                log.debug("The cache unifiedOIDCScopeClaimCache is initialized for the tenant : " + tenantId);
            }
        }
    }

    @Override
    public void addScopes(int tenantId, List<ScopeDTO> scopeClaimsMap) throws IdentityOAuth2Exception {

        super.addScopes(tenantId, scopeClaimsMap);
        if (resolveWithHierarchicalMode(tenantId)) {
            OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry = new OIDCScopeClaimCacheEntry();
            oidcScopeClaimCacheEntry.setScopeClaimMapping(scopeClaimsMap);
            unifiedOIDCScopeClaimCache.addScopeClaimMap(tenantId, oidcScopeClaimCacheEntry);
            if (log.isDebugEnabled()) {
                log.debug("The cache unifiedOIDCScopeClaimCache is added for the tenant : " + tenantId);
            }
        }
    }

    @Deprecated
    public void addScope(int tenantId, String scope, String[] claimsList) throws IdentityOAuth2Exception {

        super.addScope(tenantId, scope, claimsList);
        if (resolveWithHierarchicalMode(tenantId)) {
            unifiedOIDCScopeClaimCache.clearScopeClaimMap(tenantId);
            if (log.isDebugEnabled()) {
                log.debug("The cache unifiedOIDCScopeClaimCache is cleared for the tenant : " + tenantId);
            }
        }
    }

    @Override
    public void addScope(ScopeDTO scope, int tenantId) throws IdentityOAuth2Exception {

        super.addScope(scope, tenantId);
        if (resolveWithHierarchicalMode(tenantId)) {
            unifiedOIDCScopeClaimCache.clearScopeClaimMap(tenantId);
            if (log.isDebugEnabled()) {
                log.debug("The cache unifiedOIDCScopeClaimCache is cleared for the tenant : " + tenantId);
            }
        }
    }

    @Override
    public List<ScopeDTO> getScopes(int tenantId) throws IdentityOAuth2Exception {

        if (resolveWithHierarchicalMode(tenantId)) {
            OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry =
                    unifiedOIDCScopeClaimCache.getScopeClaimMap(tenantId);
            oidcScopeClaimCacheEntry = loadOIDCScopeClaims(tenantId, oidcScopeClaimCacheEntry);
            return oidcScopeClaimCacheEntry.getScopeClaimMapping();
        } else {
            return scopeClaimMappingDAOImpl.getScopes(tenantId);
        }
    }

    @Override
    public List<String> getScopeNames(int tenantId) throws IdentityOAuth2Exception {

        if (resolveWithHierarchicalMode(tenantId)) {
            OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry = unifiedOIDCScopeClaimCache.getScopeClaimMap(tenantId);
            oidcScopeClaimCacheEntry = loadOIDCScopeClaims(tenantId, oidcScopeClaimCacheEntry);
            List<String> scopes = new ArrayList<>();
            for (ScopeDTO scopeDTO : oidcScopeClaimCacheEntry.getScopeClaimMapping()) {
                scopes.add(scopeDTO.getName());
            }
            return scopes;
        } else {
            return scopeClaimMappingDAOImpl.getScopeNames(tenantId);
        }
    }

    @Override
    public void deleteScope(String scope, int tenantId) throws IdentityOAuth2Exception {

        super.deleteScope(scope, tenantId);
        if (resolveWithHierarchicalMode(tenantId)) {
            unifiedOIDCScopeClaimCache.clearScopeClaimMap(tenantId);
            if (log.isDebugEnabled()) {
                log.debug("OIDC scope claims mapping deleted from the unifiedOIDCScopeClaimCache for tenant: "
                        + tenantId);
            }
        }
    }

    @Deprecated
    public void updateScope(String scope, int tenantId, List<String> addClaims, List<String> deleteClaims)
            throws IdentityOAuth2Exception {

        super.updateScope(scope, tenantId, addClaims, deleteClaims);
        if (resolveWithHierarchicalMode(tenantId)) {
            unifiedOIDCScopeClaimCache.clearScopeClaimMap(tenantId);
            if (log.isDebugEnabled()) {
                log.debug("The cache unifiedOIDCScopeClaimCache is cleared for the tenant : " + tenantId);
            }
        }
    }

    @Override
    public void updateScope(ScopeDTO scope, int tenantId) throws IdentityOAuth2Exception {

        super.updateScope(scope, tenantId);
        if (resolveWithHierarchicalMode(tenantId)) {
            unifiedOIDCScopeClaimCache.clearScopeClaimMap(tenantId);
            if (log.isDebugEnabled()) {
                log.debug("The cache unifiedOIDCScopeClaimCache is cleared for the tenant : " + tenantId);
            }
        }
    }

    @Override
    public ScopeDTO getClaims(String scope, int tenantId) throws IdentityOAuth2Exception {

        if (resolveWithHierarchicalMode(tenantId)) {
            OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry = unifiedOIDCScopeClaimCache.getScopeClaimMap(tenantId);
            oidcScopeClaimCacheEntry = loadOIDCScopeClaims(tenantId, oidcScopeClaimCacheEntry);
            ScopeDTO scopeDTO = new ScopeDTO();
            for (ScopeDTO scopeObj : oidcScopeClaimCacheEntry.getScopeClaimMapping()) {
                if (scope.equals(scopeObj.getName()) && scopeObj.getClaim() != null) {
                    scopeDTO = scopeObj;
                }
            }
            return scopeDTO;
        } else {
            return scopeClaimMappingDAOImpl.getClaims(scope, tenantId);
        }
    }

    @Override
    public boolean hasScopesPopulated(int tenantId) throws IdentityOAuth2Exception {

        if (resolveWithHierarchicalMode(tenantId)) {
            return super.hasScopesPopulated(tenantId);
        } else {
            return scopeClaimMappingDAOImpl.hasScopesPopulated(tenantId);
        }
    }

    @Override
    public boolean isScopeExist(String scope, int tenantId) throws IdentityOAuth2Exception {

        if (resolveWithHierarchicalMode(tenantId)) {
            return super.isScopeExist(scope, tenantId);
        } else {
            return scopeClaimMappingDAOImpl.isScopeExist(scope, tenantId);
        }
    }

    @Override
    public ScopeDTO getScope(String scopeName, int tenantId) throws IdentityOAuth2Exception {

        if (resolveWithHierarchicalMode(tenantId)) {
            OIDCScopeClaimCacheEntry oidcScopeClaimCacheEntry = unifiedOIDCScopeClaimCache.getScopeClaimMap(tenantId);
            if (oidcScopeClaimCacheEntry != null) {
                if (!oidcScopeClaimCacheEntry.getScopeClaimMapping().isEmpty()) {
                    for (ScopeDTO scopeObj : oidcScopeClaimCacheEntry.getScopeClaimMapping()) {
                        if (scopeName.equals(scopeObj.getName())) {
                            return scopeObj;
                        }
                    }
                }
            }
            return super.getScope(scopeName, tenantId);
        } else {
            return scopeClaimMappingDAOImpl.getScope(scopeName, tenantId);
        }
    }

    private OIDCScopeClaimCacheEntry loadOIDCScopeClaims(int tenantId, OIDCScopeClaimCacheEntry
            oidcScopeClaimCacheEntry) throws IdentityOAuth2Exception {

        if (oidcScopeClaimCacheEntry == null || oidcScopeClaimCacheEntry.getScopeClaimMapping().isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Cache miss for OIDC scopes claims mapping for tenant: " + tenantId);
            }
            oidcScopeClaimCacheEntry = new OIDCScopeClaimCacheEntry();
            List<ScopeDTO> scopeClaims = super.getScopes(tenantId);

            oidcScopeClaimCacheEntry.setScopeClaimMapping(scopeClaims);
            unifiedOIDCScopeClaimCache.addScopeClaimMap(tenantId, oidcScopeClaimCacheEntry);
            if (log.isDebugEnabled()) {
                log.debug("OIDC scopes and mapped claims are loaded from the database and inserted to the cache for " +
                        "the tenant : " + tenantId);
            }
        }
        return oidcScopeClaimCacheEntry;
    }

    /**
     * Checks whether to resolve the OIDC scopes for the hierarchical inheritance model.
     *
     * @param tenantId The domain of the tenant.
     * @return true if hierarchical inheritance is enabled, false otherwise.
     */
    private boolean resolveWithHierarchicalMode(int tenantId) throws IdentityOAuth2Exception {

        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        try {
            return Utils.isClaimAndOIDCScopeInheritanceEnabled(tenantDomain);
        } catch (OrganizationManagementException e) {
            if (isOrganization(tenantId)) {
                throw new IdentityOAuth2Exception(String.format("Error occurred while resolving the organization " +
                                "id of tenant: %s with domain : %s", tenantId, tenantDomain));
            }
            /*
             * If it is not a child organization, i.e., if it is a root organization, hierarchical mode is essentially
             * just the additional DAO layer caching to help with future merging operations of child organizations.
             * Therefore, for instances such as listing the root organizations, where one root organization might
             * require resolving another root organization's tenant, we can simply proceed without the caching.
             */
            return false;
        }
    }

    /**
     * Checks whether a given tenant is an organization, i.e., whether it is a child of a root organization.
     *
     * @param tenantId The id of the tenant to be checked,
     * @return true if the tenant is an organization, false otherwise.
     * @throws IdentityOAuth2Exception If an error occurs when checking whether the tenant is an organization.
     */
    private boolean isOrganization(int tenantId) throws IdentityOAuth2Exception {

        try {
            return OrganizationManagementUtil.isOrganization(tenantId);
        } catch (OrganizationManagementException e) {
            throw new IdentityOAuth2Exception("Error while checking whether tenant: " + tenantId
                    + " is an organization", e);
        }
    }
}
