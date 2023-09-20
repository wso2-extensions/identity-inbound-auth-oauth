package org.wso2.carbon.identity.oauth2.claim.resolver;

import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

/**
 * Claim resolver interface.
 */
public interface ClaimResolver {

    /**
     * Resolve the subject claim.
     *
     * @param serviceProvider Service provider.
     * @param user            Authenticated user.
     * @return Subject claim.
     * @throws IdentityOAuth2Exception If an error occurred while resolving the subject claim.
     */
    String resolveSubjectClaim(ServiceProvider serviceProvider, AuthenticatedUser user) throws IdentityOAuth2Exception;
}
