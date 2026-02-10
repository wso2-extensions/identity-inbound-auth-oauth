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

package org.wso2.carbon.identity.oauth.endpoint.ciba;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.oauth.ciba.common.AuthReqStatus;
import org.wso2.carbon.identity.oauth.ciba.common.CibaConstants;
import org.wso2.carbon.identity.oauth.ciba.dao.CibaDAOFactory;
import org.wso2.carbon.identity.oauth.ciba.exceptions.CibaCoreException;
import org.wso2.carbon.identity.oauth.ciba.model.CibaAuthCodeDO;
import org.wso2.carbon.identity.oauth.common.OAuth2ErrorCodes;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.endpoint.authz.OAuth2AuthzEndpoint;
import org.wso2.carbon.identity.oauth.endpoint.exception.InvalidRequestParentException;
import org.wso2.carbon.identity.oauth.endpoint.util.EndpointUtil;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.CIBA_AUTH_CODE_KEY;
import static org.wso2.carbon.identity.oauth.ciba.common.CibaConstants.CIBA_SUCCESS_ENDPOINT_PATH;

/**
 * Rest implementation for ciba user authentication flow.
 */
@Path("/ciba_auth")
public class UserAuthenticationEndpoint {

    private static final Log log = LogFactory.getLog(UserAuthenticationEndpoint.class);
    private OAuth2AuthzEndpoint oAuth2AuthzEndpoint = new OAuth2AuthzEndpoint();
    public static final String ERROR = "error";
    public static final String INVALID_CODE_ERROR_KEY = "invalid.authCodeKey";

    @GET
    @Path("/")
    @Consumes("application/x-www-form-urlencoded")
    @Produces("text/html")
    public Response cibaAuth(@Context HttpServletRequest request, @Context HttpServletResponse response)
            throws InvalidRequestParentException, OAuthSystemException {

        // The user (authorization device) has invoked this endpoint to authenticate with their received notification.
        // Here we directly call the framework after validation to continue the authentication flow.
        String authCodeKey = request.getParameter(CIBA_AUTH_CODE_KEY);

        try {
            if (StringUtils.isBlank(authCodeKey)) {
                if (log.isDebugEnabled()) {
                    log.debug("authCodeKey is missing in the request.");
                }
                String error = ServiceURLBuilder.create().addPath(CIBA_SUCCESS_ENDPOINT_PATH)
                        .addParameter(ERROR, INVALID_CODE_ERROR_KEY).build().getAbsolutePublicURL();
                return Response.status(HttpServletResponse.SC_BAD_REQUEST).location(URI.create(error)).build();
            }
            CibaAuthCodeDO cibaAuthCodeDO = CibaDAOFactory.getInstance().getCibaAuthMgtDAO()
                    .getCibaAuthCode(authCodeKey);

            if (!isExpiredCibaAuthCode(cibaAuthCodeDO)) {
                CommonAuthRequestWrapper commonAuthRequestWrapper = new CommonAuthRequestWrapper(request);
                commonAuthRequestWrapper.setParameter(
                        org.wso2.carbon.identity.openidconnect.model.Constants.SCOPE,
                        OAuth2Util.buildScopeString(cibaAuthCodeDO.getScopes()));
                commonAuthRequestWrapper.setParameter(org.wso2.carbon.identity.openidconnect.model.Constants
                        .RESPONSE_TYPE, CibaConstants.RESPONSE_TYPE_VALUE);
                commonAuthRequestWrapper.setParameter(org.wso2.carbon.identity.openidconnect.model.Constants.NONCE,
                        cibaAuthCodeDO.getAuthReqId());
                commonAuthRequestWrapper.setParameter(org.wso2.carbon.identity.openidconnect.model.Constants.CLIENT_ID,
                        cibaAuthCodeDO.getConsumerKey());
                commonAuthRequestWrapper.setAttribute(OAuthConstants.PKCE_UNSUPPORTED_FLOW, true);
                return oAuth2AuthzEndpoint.authorize(commonAuthRequestWrapper, response);
            } else {
                String error = ServiceURLBuilder.create().addPath(CIBA_SUCCESS_ENDPOINT_PATH)
                        .addParameter(ERROR, INVALID_CODE_ERROR_KEY).build().getAbsolutePublicURL();
                return Response.status(HttpServletResponse.SC_BAD_REQUEST).location(URI.create(error)).build();
            }
        } catch (CibaCoreException e) {
            return handleCibaCoreException(e);
        } catch (URISyntaxException e) {
            return handleURISyntaxException(e);
        } catch (URLBuilderException e) {
            return handleURLBuilderException(e);
        }
    }

    /**
     * Handle CibaCoreException.
     *
     * @param e CibaCoreException
     * @return Response
     * @throws OAuthSystemException OAuthSystemException
     */
    private Response handleCibaCoreException(CibaCoreException e) throws OAuthSystemException {

        if (log.isDebugEnabled()) {
            log.debug(e.getMessage(), e);
        }
        OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_BAD_REQUEST).
                setError(OAuth2ErrorCodes.INVALID_REQUEST).setErrorDescription("Invalid Request").buildJSONMessage();
        return Response.status(response.getResponseStatus()).header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE,
                EndpointUtil.getRealmInfo()).entity(response.getBody()).build();
    }

    /**
     * Handle URISyntaxException.
     *
     * @param e URISyntaxException
     * @return Response
     * @throws OAuthSystemException OAuthSystemException
     */
    private Response handleURISyntaxException(URISyntaxException e) throws OAuthSystemException {

        log.error("Error while parsing string as an URI reference.", e);
        OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).
                setError(OAuth2ErrorCodes.SERVER_ERROR).setErrorDescription("Internal Server Error")
                .buildJSONMessage();
        return Response.status(response.getResponseStatus()).header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE,
                EndpointUtil.getRealmInfo()).entity(response.getBody()).build();
    }

    /**
     * Handle URLBuilderException.
     *
     * @param e URLBuilderException
     * @return
     * @throws OAuthSystemException
     */
    private Response handleURLBuilderException(URLBuilderException e) throws OAuthSystemException {

        log.error("Error occurred while sending request to authentication framework.", e);
        OAuthResponse response = OAuthASResponse.errorResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).
                setError(OAuth2ErrorCodes.SERVER_ERROR).setErrorDescription("Internal Server Error")
                .buildJSONMessage();
        return Response.status(response.getResponseStatus()).header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE,
                EndpointUtil.getRealmInfo()).entity(response.getBody()).build();
    }

    /**
     * Check whether the ciba authentication request is expired.
     *
     * @param cibaAuthCodeDO CibaAuthCodeDO
     * @return True if the ciba authentication request is expired.
     * @throws CibaCoreException Error while checking the ciba authentication request status.
     */
    private boolean isExpiredCibaAuthCode(CibaAuthCodeDO cibaAuthCodeDO) throws CibaCoreException {

        if (cibaAuthCodeDO == null) {
            return true;
        }
        // If the status is not REQUESTED, then the authentication request is already completed.
        return cibaAuthCodeDO.getAuthReqStatus() != AuthReqStatus.REQUESTED;
    }
}
