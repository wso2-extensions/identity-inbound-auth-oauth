/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.authcontext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.api.ClaimManager;
import org.wso2.carbon.user.api.ClaimMapping;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.SortedMap;
import java.util.TreeMap;

/**
 * This class is the default implementation of ClaimsRetriever.
 * It reads user claim values from the default carbon user store.
 * The user claims are encoded to the token in the natural order of the claimURIs.
 * To engage this class its fully qualified class name should be mentioned under
 * identity.xml -> OAuth -> TokenGeneration -> ClaimsRetrieverImplClass
 */
public class DefaultClaimsRetriever implements ClaimsRetriever {

    public static final String DEFAULT_DIALECT_URI = "http://wso2.org/claims";

    private String dialectURI;

    private Log log = LogFactory.getLog(DefaultClaimsRetriever.class);

    /**
     * Reads the DialectURI of the ClaimURIs to be retrieved from identity.xml ->
     * OAuth -> TokenGeneration -> ConsumerDialectURI.
     * If not configured it uses http://wso2.org/claims as default
     */
    @Override
    public void init() {

        dialectURI = OAuthServerConfiguration.getInstance().getConsumerDialectURI();
        if (dialectURI == null) {
            dialectURI = DEFAULT_DIALECT_URI;
        }
    }

    @Override
    public SortedMap<String, String> getClaims(String endUserName, String[] requestedClaims)
            throws IdentityOAuth2Exception {

        SortedMap<String, String> claimValues;
        int tenantId = MultitenantConstants.SUPER_TENANT_ID;
        try {
            tenantId = OAuth2Util.getTenantIdFromUserName(endUserName);
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(endUserName);
            UserStoreManager userStoreManager = OAuthComponentServiceHolder.getInstance().getRealmService().
                    getTenantUserRealm(tenantId).getUserStoreManager();
            claimValues = new TreeMap(userStoreManager.getUserClaimValues(tenantAwareUsername, requestedClaims, null));
        } catch (UserStoreException e) {
            throw new IdentityOAuth2Exception("Error while reading claims for user : " + endUserName, e);
        }
        return claimValues;
    }

    @Override
    public String[] getDefaultClaims(String endUserName) throws IdentityOAuth2Exception {

        int tenantId = MultitenantConstants.SUPER_TENANT_ID;
        try {
            tenantId = OAuth2Util.getTenantIdFromUserName(endUserName);
            // if no claims were requested, return all
            if (log.isDebugEnabled()) {
                log.debug("No claims set requested. Returning all claims in the dialect");
            }
            ClaimManager claimManager =
                    OAuthComponentServiceHolder.getInstance().getRealmService().getTenantUserRealm(tenantId)
                            .getClaimManager();
            ClaimMapping[] claims = claimManager.getAllClaimMappings(dialectURI);
            return claimToString(claims);
        } catch (UserStoreException e) {
            throw new IdentityOAuth2Exception("Error while reading default claims for user : " + endUserName, e);
        }
    }

    /**
     * Helper method to convert array of <code>Claim</code> object to
     * array of <code>String</code> objects corresponding to the ClaimURI values.
     */
    private String[] claimToString(ClaimMapping[] claims) {

        String[] temp = new String[claims.length];
        for (int i = 0; i < claims.length; i++) {
            temp[i] = claims[i].getClaim().getClaimUri();
        }
        return temp;
    }
}
