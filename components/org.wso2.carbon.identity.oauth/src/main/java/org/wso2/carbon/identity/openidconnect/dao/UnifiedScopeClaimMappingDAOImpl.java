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
import org.wso2.carbon.identity.core.util.LambdaExceptionUtils;
import org.wso2.carbon.identity.oauth.dto.ScopeDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.resource.hierarchy.traverse.service.exception.OrgResourceHierarchyTraverseException;
import org.wso2.carbon.identity.organization.resource.hierarchy.traverse.service.strategy.FirstFoundAggregationStrategy;
import org.wso2.carbon.identity.organization.resource.hierarchy.traverse.service.strategy.MergeAllAggregationStrategy;
import org.wso2.carbon.user.api.UserStoreException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Unified implementation of {@link ScopeClaimMappingDAO}.
 * This handles {@link ScopeDTO} related merging and inheritance operations.
 */
public class UnifiedScopeClaimMappingDAOImpl extends CacheBackedScopeClaimMappingDAOImpl {

    private static final Log log = LogFactory.getLog(UnifiedScopeClaimMappingDAOImpl.class);

    @Override
    public List<ScopeDTO> getScopes(int tenantId) throws IdentityOAuth2Exception {

        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        List<ScopeDTO> scopeDTOList = null;
        try {
            String organizationId = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(tenantDomain);
            scopeDTOList = OAuth2ServiceComponentHolder.getInstance().getOrgResourceResolverService()
                    .getResourcesFromOrgHierarchy(organizationId,
                            LambdaExceptionUtils.rethrowFunction(this::retrieveScopesFromHierarchy),
                            new MergeAllAggregationStrategy<>(this::mergeScopesInHierarchy)
                    );
        } catch (OrganizationManagementException | OrgResourceHierarchyTraverseException e) {
            handleHierarchyTraversalException(tenantId, tenantDomain, e);
        }
        return scopeDTOList;
    }

    /**
     * Retrieves scopes for an organization in the hierarchy during sub-organization scope aggregation.
     *
     * @param orgId The organization id of the tenant for which the scopes need to be retrieved.
     * @return The scopes of the given tenant.
     * @throws IdentityOAuth2Exception If an error occurs when getting the tenant id or the scopes.
     */
    private Optional<List<ScopeDTO>> retrieveScopesFromHierarchy(String orgId)
            throws IdentityOAuth2Exception {

        int tenantId = getTenantId(orgId);
        List<ScopeDTO> scopeDTOs = super.getScopes(tenantId);
        return Optional.ofNullable(scopeDTOs);
    }

    /**
     * Merges scopes in the hierarchy and removes duplicates found at higher levels as priority is given
     * to the lower levels.
     * <p>
     * Currently, creating scopes at the sub-organization level is not supported, therefore, the scopes
     * will be picked up from the root organization, however, this method is expected to support scopes
     * created by sub-organizations if and when this is introduced.
     *
     * @param aggregatedScopeDTOs The scopes aggregated from the child organizations so far.
     * @param tenantScopeDTOs     The scopes of the current tenant being considered.
     * @return The merged list of scopes up to the specific tenant being considered.
     */
    private List<ScopeDTO> mergeScopesInHierarchy(
            List<ScopeDTO> aggregatedScopeDTOs, List<ScopeDTO> tenantScopeDTOs) {

        Map<String, ScopeDTO> existingScopeDTOs = aggregatedScopeDTOs.stream()
                .collect(Collectors.toMap(ScopeDTO::getName, Function.identity()));
        for (ScopeDTO tenantScopeDTO : tenantScopeDTOs) {
            String scopeDTOName = tenantScopeDTO.getName();
            if (!existingScopeDTOs.containsKey(scopeDTOName)) {
                aggregatedScopeDTOs.add(tenantScopeDTO);
            }
        }
        return aggregatedScopeDTOs;
    }

    @Override
    public List<String> getScopeNames(int tenantId) throws IdentityOAuth2Exception {

        return getScopeNamesFromDAO(tenantId);
    }

    @Override
    public ScopeDTO getClaims(String scope, int tenantId) throws IdentityOAuth2Exception {

        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        ScopeDTO scopeDTO = null;
        try {
            String organizationId = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(tenantDomain);
            scopeDTO = OAuth2ServiceComponentHolder.getInstance().getOrgResourceResolverService()
                    .getResourcesFromOrgHierarchy(organizationId, LambdaExceptionUtils.rethrowFunction(orgId ->
                                    retrieveScopeClaimsFromHierarchy(scope, orgId)),
                            new MergeAllAggregationStrategy<>(this::mergeScopeClaimsInHierarchy)
                    );
        } catch (OrganizationManagementException | OrgResourceHierarchyTraverseException e) {
            handleHierarchyTraversalException(tenantId, tenantDomain, e);
        }
        return scopeDTO;
    }

    /**
     * Retrieves scope names for an organization in the hierarchy during sub-organization scope aggregation.
     *
     * @param scope The scope for which the claims need to be retrieved.
     * @param orgId The organization id of the tenant for which the scopes need to be retrieved.
     * @return The claims of the given tenant.
     * @throws IdentityOAuth2Exception If an error occurs when getting the tenant id or the scope claims.
     */
    private Optional<ScopeDTO> retrieveScopeClaimsFromHierarchy(String scope, String orgId)
            throws IdentityOAuth2Exception {

        int tenantId = getTenantId(orgId);
        ScopeDTO scopeDTO = OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().
                getClaims(scope, tenantId);
        return Optional.ofNullable(scopeDTO);
    }

    /**
     * Merges scope claims in the hierarchy and removes duplicates found at higher levels as priority is given
     * to the lower levels.
     * <p>
     * Currently, creating scopes at the sub-organization level is not supported, therefore, the scope claims
     * will be picked up from the root organization, however, this method is expected to support scopes created
     * by sub-organizations if and when this is introduced.
     *
     * @param aggregatedScopeClaims The scope claims aggregated from the child organizations so far.
     * @param tenantScopeClaims     The scope claims of the current tenant being considered.
     * @return The merged list of scope names up to the specific tenant being considered.
     */
    private ScopeDTO mergeScopeClaimsInHierarchy(
            ScopeDTO aggregatedScopeClaims, ScopeDTO tenantScopeClaims) {

        Set<String> existingClaims = new HashSet<>(Arrays.asList(aggregatedScopeClaims.getClaim()));

        for (String claim : tenantScopeClaims.getClaim()) {
            if (!existingClaims.contains(claim)) {
                aggregatedScopeClaims.addNewClaimToExistingClaims(claim);
            }
        }
        return aggregatedScopeClaims;
    }

    @Override
    public boolean hasScopesPopulated(int tenantId) throws IdentityOAuth2Exception {

        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        Boolean scopeExists = null;
        try {
            String organizationId = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(tenantDomain);
            scopeExists = OAuth2ServiceComponentHolder.getInstance().getOrgResourceResolverService()
                    .getResourcesFromOrgHierarchy(organizationId,
                            LambdaExceptionUtils.rethrowFunction(this::retrieveHasScopesPopulatedInHierarchy),
                            new FirstFoundAggregationStrategy<>()
                    );
        } catch (OrganizationManagementException | OrgResourceHierarchyTraverseException e) {
            handleHierarchyTraversalException(tenantId, tenantDomain, e);
        }
        return scopeExists != null && scopeExists;
    }

    /**
     * Checks whether scopes have been populated for the given organization in the hierarchy.
     *
     * @param orgId The organization id of the tenant for which the scope needs to be retrieved.
     * @return an optional containing true if it exists and an empty optional if it doesn't.
     * @throws IdentityOAuth2Exception If an error occurs when getting the tenant id or checking the scope existence.
     */
    private Optional<Boolean> retrieveHasScopesPopulatedInHierarchy(String orgId)
            throws IdentityOAuth2Exception {

        int tenantId = getTenantId(orgId);
        boolean scopeExists = OAuthTokenPersistenceFactory.getInstance().
                getScopeClaimMappingDAO().hasScopesPopulated(tenantId);
        if (scopeExists) {
            return Optional.of(true);
        }
        return Optional.empty();
    }

    @Override
    public boolean isScopeExist(String scope, int tenantId) throws IdentityOAuth2Exception {

        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        Boolean scopeExists = null;
        try {
            String organizationId = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(tenantDomain);
            scopeExists = OAuth2ServiceComponentHolder.getInstance().getOrgResourceResolverService()
                    .getResourcesFromOrgHierarchy(organizationId, LambdaExceptionUtils.rethrowFunction(orgId ->
                                    retrieveScopeExistenceInHierarchy(scope, orgId)),
                            new FirstFoundAggregationStrategy<>()
                    );
        } catch (OrganizationManagementException | OrgResourceHierarchyTraverseException e) {
            handleHierarchyTraversalException(tenantId, tenantDomain, e);
        }
        return scopeExists != null && scopeExists;
    }

    /**
     * Checks whether a scope exists in the given organization in the hierarchy.
     * @param scope The name of the scope to be retrieved.
     * @param orgId The organization id of the tenant for which the scope needs to be retrieved.
     * @return an optional containing true if it exists and an empty optional if it doesn't.
     * @throws IdentityOAuth2Exception If an error occurs when getting the tenant id or checking the scope existence.
     */
    private Optional<Boolean> retrieveScopeExistenceInHierarchy(String scope, String orgId)
            throws IdentityOAuth2Exception {

        int tenantId = getTenantId(orgId);
        boolean scopeExists = OAuthTokenPersistenceFactory.getInstance().
                getScopeClaimMappingDAO().isScopeExist(scope, tenantId);
        if (scopeExists) {
            return Optional.of(true);
        }
        return Optional.empty();
    }

    /**
     * Get OIDC scope details by scope name.
     *
     * @param scopeName Scope name.
     * @param tenantId  Tenant ID.
     * @return OIDC scope object.
     * @throws IdentityOAuth2Exception
     */
    @Override
    public ScopeDTO getScope(String scopeName, int tenantId) throws IdentityOAuth2Exception {

        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        ScopeDTO scopeDTO = null;
        try {
            String organizationId = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(tenantDomain);
            scopeDTO = OAuth2ServiceComponentHolder.getInstance().getOrgResourceResolverService()
                    .getResourcesFromOrgHierarchy(organizationId, LambdaExceptionUtils.rethrowFunction(orgId ->
                                    retrieveScopeFromHierarchy(scopeName, orgId)),
                            new FirstFoundAggregationStrategy<>()
                    );
        } catch (OrgResourceHierarchyTraverseException | OrganizationManagementException e) {
            handleHierarchyTraversalException(tenantId, tenantDomain, e);
        }
        return scopeDTO;
    }

    /**
     * Retrieves a given scope from an organization in the hierarchy
     * during sub-organization scope aggregation if it exists.
     *
     * @param scopeName The name of the scope to be retrieved.
     * @param orgId     The organization id of the tenant for which the scope needs to be retrieved.
     * @return The scope in the given tenant, if it exists.
     *
     * @throws IdentityOAuth2Exception If an error occurs when getting the tenant id or the scope.
     */
    private Optional<ScopeDTO> retrieveScopeFromHierarchy(String scopeName, String orgId)
            throws IdentityOAuth2Exception {

        int tenantId = getTenantId(orgId);
        ScopeDTO scopeDTO = OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().
                getScope(scopeName, tenantId);
        return Optional.ofNullable(scopeDTO);
    }

    /**
     * Retrieves the scope names from the DAO layer based on whether OIDC scope inheritance is enabled or not.
     *
     * @param tenantId     The tenant id of the tenant for which the scope names need to be retrieved.
     * @return The scope names for the given tenant.
     * @throws IdentityOAuth2Exception If an error occurs when getting the tenant id or the scopes.
     */
    private List<String> getScopeNamesFromDAO(int tenantId) throws IdentityOAuth2Exception {

        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        List<String> scopeList = null;
        try {
            String organizationId = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(tenantDomain);
            scopeList =  OAuth2ServiceComponentHolder.getInstance().getOrgResourceResolverService()
                    .getResourcesFromOrgHierarchy(organizationId,
                            LambdaExceptionUtils.rethrowFunction(this::retrieveScopeNamesFromHierarchy),
                            new MergeAllAggregationStrategy<>(this::mergeScopeNamesInHierarchy)
                    );
            if (log.isDebugEnabled()) {
                log.debug("The scopes: " + String.join(",", scopeList)
                        + " are successfully loaded for the tenant: " + tenantId);
            }
        } catch (OrganizationManagementException | OrgResourceHierarchyTraverseException e) {
            handleHierarchyTraversalException(tenantId, tenantDomain, e);
        }
        return scopeList;
    }

    /**
     * Retrieves scope names for an organization in the hierarchy during sub-organization scope aggregation.
     *
     * @param orgId The organization id of the tenant for which the scopes need to be retrieved.
     * @return The scopes of the given tenant.
     * @throws IdentityOAuth2Exception If an error occurs when getting the tenant id or the scopes.
     */
    private Optional<List<String>> retrieveScopeNamesFromHierarchy(String orgId)
            throws IdentityOAuth2Exception {

        int tenantId = getTenantId(orgId);
        List<String> scopeNames = OAuthTokenPersistenceFactory.getInstance().getScopeClaimMappingDAO().
                getScopeNames(tenantId);
        return Optional.ofNullable(scopeNames);
    }

    /**
     * Merges scope names in the hierarchy and removes duplicates found at higher levels as priority is given
     * to the lower levels.
     * <p>
     * Currently, creating scopes at the sub-organization level is not supported, therefore, the scope names
     * will be picked up from the root organization, however, this method is expected to support scopes created
     * by sub-organizations if and when this is introduced.
     *
     * @param aggregatedScopeNames The scope names aggregated from the child organizations so far.
     * @param tenantScopeNames     The scope names of the current tenant being considered.
     * @return The merged list of scope names up to the specific tenant being considered.
     */
    private List<String> mergeScopeNamesInHierarchy(
            List<String> aggregatedScopeNames, List<String> tenantScopeNames) {

        Set<String> scopeSet = new HashSet<>(aggregatedScopeNames);
        scopeSet.addAll(tenantScopeNames);
        return new ArrayList<>(scopeSet);
    }

    /**
     * Gets the tenant id corresponding to a given organization id.
     *
     * @param orgId The organization id of the tenant to be retrieved.
     * @return The id of the tenant.
     * @throws IdentityOAuth2Exception If an error occurs when getting the tenant id.
     */
    private int getTenantId(String orgId) throws IdentityOAuth2Exception {

        try {
            String tenantDomain = OAuth2ServiceComponentHolder.getInstance()
                    .getOrganizationManager().resolveTenantDomain(orgId);
            return OAuth2ServiceComponentHolder.getInstance().getRealmService()
                    .getTenantManager().getTenantId(tenantDomain);
        } catch (OrganizationManagementException | UserStoreException e) {
            throw new IdentityOAuth2Exception(String.format("Error occurred while resolving the tenant id for" +
                            " organization: %s during hierarchical aggregation", orgId), e);
        }
    }

    /**
     * Handles exceptions {@link OrganizationManagementException} and {@link OrgResourceHierarchyTraverseException}.
     *
     * @param tenantId     The id of the tenant for which the exception occurred.
     * @param tenantDomain The domain of the tenant for which the exception occurred.
     * @param e            The exception to be handled.
     * @throws IdentityOAuth2Exception To handle the exceptions.
     */
    private void handleHierarchyTraversalException(int tenantId, String tenantDomain, Exception e)
            throws IdentityOAuth2Exception {

        throw new IdentityOAuth2Exception(String.format("Error occurred while traversing the organization " +
                "hierarchy of tenant: %s with domain: %s", tenantId, tenantDomain), e);
    }
}
