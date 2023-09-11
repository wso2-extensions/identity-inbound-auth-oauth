package org.wso2.carbon.identity.oauth2.claim.resolver;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.Optional;

import static org.apache.commons.lang.StringUtils.isNotBlank;

/**
 * Default implementation of {@link ClaimResolver}.
 */
public class ClaimResolverImpl implements ClaimResolver {

    private static final Log log = LogFactory.getLog(ClaimResolverImpl.class);

    @Override
    public String resolveSubjectClaim(ServiceProvider serviceProvider, AuthenticatedUser authenticatedUser)
            throws IdentityOAuth2Exception {

        String userTenantDomain = authenticatedUser.getTenantDomain();
        String subject;
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        String subjectClaimUri = getSubjectClaimUriInLocalDialect(serviceProvider);
        if (StringUtils.isNotBlank(subjectClaimUri)) {
            try {
                subject = getSubjectClaimFromUserStore(subjectClaimUri, authenticatedUser);
                if (StringUtils.isBlank(subject)) {
                    // Set username as the subject claim since we have no other option
                    subject = getDefaultSubject(serviceProvider, authenticatedUser);
                    log.warn("Cannot find subject claim: " + subjectClaimUri + " for user:"
                            + authenticatedUser.getLoggableUserId()
                            + ". Defaulting to username: " + subject + " as the subject identifier.");
                }
                // Get the subject claim in the correct format (ie. tenantDomain or userStoreDomain appended)
                subject = getFormattedSubjectClaim(serviceProvider, subject, userStoreDomain, userTenantDomain);
            } catch (IdentityException e) {
                String error = "Error occurred while getting user claim for user: "
                        + authenticatedUser.getLoggableUserId() + ", claim" +
                        ": " +
                        subjectClaimUri;
                throw new IdentityOAuth2Exception(error, e);
            } catch (org.wso2.carbon.user.core.UserStoreException e) {
                String error = "Error occurred while getting subject claim: " + subjectClaimUri + " for user: "
                        + authenticatedUser.getLoggableUserId();
                throw new IdentityOAuth2Exception(error, e);
            }
        } else {
            try {
                subject = getDefaultSubject(serviceProvider, authenticatedUser);
                subject = getFormattedSubjectClaim(serviceProvider, subject, userStoreDomain, userTenantDomain);
            } catch (UserIdNotFoundException e) {
                throw new IdentityOAuth2Exception("User id not found for user: "
                        + authenticatedUser.getLoggableUserId(), e);
            }
            if (log.isDebugEnabled()) {
                log.debug("No subject claim defined for service provider: " + serviceProvider.getApplicationName()
                        + ". Using username as the subject claim.");
            }

        }
        return subject;
    }

    private String getSubjectClaimFromUserStore(String subjectClaimUri, AuthenticatedUser authenticatedUser)
            throws org.wso2.carbon.user.core.UserStoreException, IdentityException {

        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) IdentityTenantUtil
                .getRealm(authenticatedUser.getTenantDomain(), authenticatedUser.toFullQualifiedUsername())
                .getUserStoreManager();
        if (OAuth2ServiceComponentHolder.getInstance().isOrganizationManagementEnabled() &&
                !userStoreManager.isExistingUserWithID(authenticatedUser.getUserId())) {
            // Fetch the user realm's user store manager corresponds to the tenant domain where the userID exists.
            userStoreManager = getUserStoreManagerFromRealmOfUserResideOrganization(authenticatedUser.getTenantDomain(),
                    authenticatedUser.getUserId()).orElse(userStoreManager);
        }
        return userStoreManager.getUserClaimValueWithID(authenticatedUser.getUserId(), subjectClaimUri, null);
    }

    /**
     * If the user is not found in the given tenant domain, check the user existence from ancestor organizations and
     * provide the correct user store manager from the user realm.
     *
     * @param tenantDomain The tenant domain of the authenticated user.
     * @param userId The ID of the authenticated user.
     * @return User store manager of the user reside organization.
     */
    private Optional<AbstractUserStoreManager> getUserStoreManagerFromRealmOfUserResideOrganization(String tenantDomain,
                                                                                                    String userId) {

        try {
            String organizationId = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(tenantDomain);
            Optional<String> userResideOrgId = OAuth2ServiceComponentHolder.getOrganizationUserResidentResolverService()
                    .resolveResidentOrganization(userId, organizationId);
            if (!userResideOrgId.isPresent()) {
                return Optional.empty();
            }
            String userResideTenantDomain = OAuth2ServiceComponentHolder.getInstance().getOrganizationManager()
                    .resolveTenantDomain(userResideOrgId.get());
            int tenantId = OAuth2ServiceComponentHolder.getInstance().getRealmService().getTenantManager()
                    .getTenantId(userResideTenantDomain);
            RealmService realmService = OAuth2ServiceComponentHolder.getInstance().getRealmService();
            return Optional.of(
                    (AbstractUserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager());
        } catch (OrganizationManagementException | UserStoreException e) {
            return Optional.empty();
        }
    }

    private String getFormattedSubjectClaim(ServiceProvider serviceProvider, String subjectClaimValue,
                                            String userStoreDomain, String tenantDomain) {

        boolean appendUserStoreDomainToSubjectClaim = serviceProvider.getLocalAndOutBoundAuthenticationConfig()
                .isUseUserstoreDomainInLocalSubjectIdentifier();

        boolean appendTenantDomainToSubjectClaim = serviceProvider.getLocalAndOutBoundAuthenticationConfig()
                .isUseTenantDomainInLocalSubjectIdentifier();

        if (appendTenantDomainToSubjectClaim) {
            subjectClaimValue = UserCoreUtil.addTenantDomainToEntry(subjectClaimValue, tenantDomain);
        }
        if (appendUserStoreDomainToSubjectClaim) {
            subjectClaimValue = IdentityUtil.addDomainToName(subjectClaimValue, userStoreDomain);
        }

        return subjectClaimValue;
    }

    private String getDefaultSubject(ServiceProvider serviceProvider, AuthenticatedUser authenticatedUser)
            throws UserIdNotFoundException {
        String subject;
        boolean useUserIdForDefaultSubject = false;
        ServiceProviderProperty[] spProperties = serviceProvider.getSpProperties();
        if (spProperties != null) {
            for (ServiceProviderProperty prop : spProperties) {
                if (IdentityApplicationConstants.USE_USER_ID_FOR_DEFAULT_SUBJECT.equals(prop.getName())) {
                    useUserIdForDefaultSubject = Boolean.parseBoolean(prop.getValue());
                    break;
                }
            }
        }
        if (useUserIdForDefaultSubject) {
            subject = authenticatedUser.getUserId();
        } else {
            subject = authenticatedUser.getUserName();
        }
        return subject;
    }

    private String getSubjectClaimUriInLocalDialect(ServiceProvider serviceProvider) {

        String subjectClaimUri = serviceProvider.getLocalAndOutBoundAuthenticationConfig().getSubjectClaimUri();
        if (log.isDebugEnabled()) {
            if (isNotBlank(subjectClaimUri)) {
                log.debug(subjectClaimUri + " is defined as subject claim for service provider: " +
                        serviceProvider.getApplicationName());
            } else {
                log.debug("No subject claim defined for service provider: " + serviceProvider.getApplicationName());
            }
        }
        // Get the local subject claim URI, if subject claim was a SP mapped one
        return getSubjectClaimUriInLocalDialect(serviceProvider, subjectClaimUri);
    }

    private String getSubjectClaimUriInLocalDialect(ServiceProvider serviceProvider, String subjectClaimUri) {

        if (isNotBlank(subjectClaimUri)) {
            ClaimConfig claimConfig = serviceProvider.getClaimConfig();
            if (claimConfig != null) {
                boolean isLocalClaimDialect = claimConfig.isLocalClaimDialect();
                ClaimMapping[] claimMappings = claimConfig.getClaimMappings();
                if (!isLocalClaimDialect && ArrayUtils.isNotEmpty(claimMappings)) {
                    for (ClaimMapping claimMapping : claimMappings) {
                        if (StringUtils.equals(claimMapping.getRemoteClaim().getClaimUri(), subjectClaimUri)) {
                            return claimMapping.getLocalClaim().getClaimUri();
                        }
                    }
                }
            }
        }
        // This means the original subjectClaimUri passed was the subject claim URI.
        return subjectClaimUri;
    }
}
