/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth.ui.util;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthConsumerAppDTO;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import javax.servlet.http.HttpServletRequest;

/**
 * Utility class for OAuth FE functionality.
 */
public class OAuthUIUtil {

    private static final Log log = LogFactory.getLog(OAuthUIUtil.class);
    private static final String SCOPE_VALIDATOR_PREFIX = "scope_validator_";
    private static final String TOKEN_TYPE_PREFIX = "token_type_";

    private OAuthUIUtil() {

    }

    /**
     * Returns the corresponding absolute endpoint URL. e.g. https://localhost:9443/oauth2/access-token
     *
     * @param endpointType It could be request-token endpoint, callback-token endpoint or access-token endpoint
     * @param oauthVersion OAuth version whether it is 1.0a or 2.0
     * @param request      HttpServletRequest coming to the FE jsp
     * @return Absolute endpoint URL.
     */
    public static String getAbsoluteEndpointURL(String endpointType, String oauthVersion, HttpServletRequest request) {

        String endpointURL = null;
        if (oauthVersion.equals(OAuthConstants.OAuthVersions.VERSION_1A)) {
            endpointURL = IdentityUtil.getServerURL("/oauth" + endpointType, true, true);
        } else {
            endpointURL = IdentityUtil.getServerURL("/oauth2" + endpointType, true, false);
        }

        return endpointURL;
    }

    public static OAuthConsumerAppDTO[] doPaging(int pageNumber, OAuthConsumerAppDTO[] oAuthConsumerAppDTOSet) {

        int itemsPerPageInt = OAuthConstants.DEFAULT_ITEMS_PER_PAGE;
        OAuthConsumerAppDTO[] returnedOAuthConsumerSet;

        int startIndex = pageNumber * itemsPerPageInt;
        int endIndex = (pageNumber + 1) * itemsPerPageInt;
        if (itemsPerPageInt < oAuthConsumerAppDTOSet.length) {
            returnedOAuthConsumerSet = new OAuthConsumerAppDTO[itemsPerPageInt];
        } else {
            returnedOAuthConsumerSet = new OAuthConsumerAppDTO[oAuthConsumerAppDTOSet.length];
        }
        for (int i = startIndex, j = 0; i < endIndex && i < oAuthConsumerAppDTOSet.length; i++, j++) {
            returnedOAuthConsumerSet[j] = oAuthConsumerAppDTOSet[i];
        }

        return returnedOAuthConsumerSet;
    }

    /**
     * This is used to verify the given URL is a valid or not
     *
     * @param uri URI to validate
     * @return true if the uri is valid
     */
    public static boolean isValidURI(String uri) {

        try {
            new URI(uri);
            return true;
        } catch (URISyntaxException e) {
            if (log.isDebugEnabled()) {
                log.debug("Malformed URL: " + uri, e);
            }
            return false;
        }
    }

    /**
     * Ensures that returned audience array is not empty and does not contain any null values.
     *
     * @param audiences
     * @return
     */
    public static boolean isAudienceNotEmpty(String[] audiences) {

        if (ArrayUtils.isEmpty(audiences)) {
            return false;
        }

        for (String audience : audiences) {
            if (StringUtils.isNotEmpty(audience) && !StringUtils.equalsIgnoreCase(audience, "null")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Generate id for the scope validator
     *
     * @param name scope validator name
     * @return scope validator id
     */
    public static String getScopeValidatorId(String name) {

        return SCOPE_VALIDATOR_PREFIX + name.replaceAll(" ", "_");
    }

    public static String getTokenTypeId(String type) {

        return TOKEN_TYPE_PREFIX + type.replaceAll(" ", "_");
    }

    /**
     * This method is to validate a URL. This method validate both absolute & relative URLs.
     *
     * @param urlString URL String.
     * @return true if valid URL, false otherwise.
     */
    public static boolean isValidURL(String urlString) {

        if (StringUtils.isBlank(urlString)) {
            String errorMsg = "Invalid URL.";
            if (log.isDebugEnabled()) {
                log.debug(errorMsg);
            }
            return false;
        }

        try {
            if (isURLRelative(urlString)) {
                // Build Absolute URL using the relative url path.
                urlString = buildAbsoluteURL(urlString);
            }
            /*
              Validate URL string using the  java.net.URL class.
              Create a URL object from the URL string representation. Throw MalformedURLException if not a valid URL.
             */
            new URL(urlString);
        } catch (MalformedURLException | URISyntaxException |  URLBuilderException e) {
            if (log.isDebugEnabled()) {
                log.debug(e.getMessage(), e);
            }
            return false;
        }
        return true;
    }

    private static boolean isURLRelative(String uriString) throws URISyntaxException {

        return !new URI(uriString).isAbsolute();
    }

    private static String buildAbsoluteURL(String contextPath) throws URLBuilderException {

        return ServiceURLBuilder.create().addPath(contextPath).build().getAbsolutePublicURL();
    }
}
