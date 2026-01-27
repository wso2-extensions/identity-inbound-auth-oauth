/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
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
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.net.URI;
import java.net.URISyntaxException;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.TimeZone;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

/**
 * REST implementation for CIBA user authentication flow.
 * 
 * This endpoint handles user authentication when they click the link received 
 * in their notification (email/SMS). It validates the authCodeKey, retrieves 
 * the CIBA session, and redirects to the authentication framework.
 */
@Path("/ciba_authorize")
public class CibaUserAuthenticationEndpoint {

    private static final Log log = LogFactory.getLog(CibaUserAuthenticationEndpoint.class);
    
    public static final String ERROR = "error";
    public static final String INVALID_AUTH_CODE_KEY = "invalid.authCodeKey";
    
    private OAuth2AuthzEndpoint oAuth2AuthzEndpoint = new OAuth2AuthzEndpoint();

    /**
     * Handles CIBA user authentication requests.
     * 
     * The user (on their authentication device) invokes this endpoint after receiving
     * a notification with the authentication link. This endpoint validates the request,
     * retrieves the CIBA session details, and triggers the authentication framework.
     *
     * @param request  HttpServletRequest
     * @param response HttpServletResponse
     * @return Response redirecting to authentication or error page
     * @throws InvalidRequestParentException If request validation fails
     * @throws OAuthSystemException If OAuth system error occurs
     */
    @GET
    @Path("/")
    @Produces("text/html")
    public Response cibaAuthorize(@Context HttpServletRequest request, @Context HttpServletResponse response)
            throws InvalidRequestParentException, OAuthSystemException {

        try {
            String authCodeKey = request.getParameter(CibaConstants.CIBA_AUTH_CODE_KEY);
            
            // Validate authCodeKey is present
            if (StringUtils.isBlank(authCodeKey)) {
                if (log.isDebugEnabled()) {
                    log.debug("authCodeKey is missing in the CIBA authentication request.");
                }
                return buildErrorResponse(INVALID_AUTH_CODE_KEY);
            }
            
            // Retrieve CIBA authentication code details from database
            CibaAuthCodeDO cibaAuthCodeDO = CibaDAOFactory.getInstance()
                    .getCibaAuthMgtDAO().getCibaAuthCode(authCodeKey);
            
            // Validate the auth code exists and is not expired/used
            if (cibaAuthCodeDO == null) {
                if (log.isDebugEnabled()) {
                    log.debug("No CIBA authentication request found for authCodeKey: " + authCodeKey);
                }
                return buildErrorResponse(INVALID_AUTH_CODE_KEY);
            }
            
            if (isExpiredOrUsedAuthCode(cibaAuthCodeDO)) {
                if (log.isDebugEnabled()) {
                    log.debug("CIBA authentication request is expired or already used for authCodeKey: " + authCodeKey);
                }
                return buildErrorResponse(INVALID_AUTH_CODE_KEY);
            }
            
            // Build the authentication request wrapper with CIBA session details
            // Override content type and method since CarbonOAuthAuthzRequest expects POST with form-urlencoded
            CommonAuthRequestWrapper commonAuthRequestWrapper = new CommonAuthRequestWrapper(request) {
                @Override
                public String getContentType() {
                    return "application/x-www-form-urlencoded";
                }
                
                @Override
                public String getHeader(String name) {
                    if ("Content-Type".equalsIgnoreCase(name)) {
                        return "application/x-www-form-urlencoded";
                    }
                    return super.getHeader(name);
                }
                
                @Override
                public String getMethod() {
                    return "POST";
                }
            };
            
            // Set client ID
            commonAuthRequestWrapper.setParameter(
                    org.wso2.carbon.identity.openidconnect.model.Constants.CLIENT_ID,
                    cibaAuthCodeDO.getConsumerKey());

            // Set response type to trigger CibaResponseTypeHandler
            commonAuthRequestWrapper.setParameter(Constants.RESPONSE_TYPE, CibaConstants.RESPONSE_TYPE_VALUE);

            // Set scope.
            String[] scopes = cibaAuthCodeDO.getScopes();
            if (scopes != null && scopes.length > 0) {
                commonAuthRequestWrapper.setParameter(
                        org.wso2.carbon.identity.openidconnect.model.Constants.SCOPE,
                        OAuth2Util.buildScopeString(scopes));
            }
            
            // Set nonce as auth_req_id for CibaResponseTypeHandler to identify the request
            commonAuthRequestWrapper.setParameter(
                    org.wso2.carbon.identity.openidconnect.model.Constants.NONCE,
                    cibaAuthCodeDO.getAuthReqId());
            
            // Mark PKCE as unsupported for CIBA flow
            commonAuthRequestWrapper.setAttribute(OAuthConstants.PKCE_UNSUPPORTED_FLOW, true);
            
            // Set client authentication context
            setClientAuthnContext(request, cibaAuthCodeDO.getConsumerKey());
            
            if (log.isDebugEnabled()) {
                log.debug("Initiating CIBA user authentication for client: " + cibaAuthCodeDO.getConsumerKey() +
                        " with auth_req_id: " + cibaAuthCodeDO.getAuthReqId());
            }
            
            // Delegate to OAuth2AuthzEndpoint to handle authentication
            return oAuth2AuthzEndpoint.authorize(commonAuthRequestWrapper, response);
            
        } catch (CibaCoreException e) {
            return handleCibaCoreException(e);
        } catch (URLBuilderException e) {
            return handleURLBuilderException(e);
        } catch (URISyntaxException e) {
            return handleURISyntaxException(e);
        }
    }

    /**
     * Sets the client authentication context to the request.
     *
     * @param request  HttpServletRequest
     * @param clientId Client ID
     */
    private void setClientAuthnContext(HttpServletRequest request, String clientId) {

        OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
        oAuthClientAuthnContext.setAuthenticated(true);
        oAuthClientAuthnContext.setClientId(clientId);
        request.setAttribute(OAuthConstants.CLIENT_AUTHN_CONTEXT, oAuthClientAuthnContext);
    }

    /**
     * Checks if the CIBA auth code is expired or already used.
     *
     * @param cibaAuthCodeDO CIBA authentication code data object
     * @return true if expired or used, false otherwise
     */
    private boolean isExpiredOrUsedAuthCode(CibaAuthCodeDO cibaAuthCodeDO) {

        // Check if status is not REQUESTED (meaning it's already been processed)
        AuthReqStatus status = (AuthReqStatus) cibaAuthCodeDO.getAuthReqStatus();
        if (status != AuthReqStatus.REQUESTED) {
            if (log.isDebugEnabled()) {
                log.debug("CIBA auth code status is " + status + ", not REQUESTED.");
            }
            return true;
        }
        
        // Check if expired
        Timestamp issuedTime = cibaAuthCodeDO.getIssuedTime();
        long expiresIn = cibaAuthCodeDO.getExpiresIn();
        long currentTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone(CibaConstants.UTC)).getTimeInMillis();
        
        if (currentTimeInMillis > issuedTime.getTime() + (expiresIn * CibaConstants.SEC_TO_MILLISEC_FACTOR)) {
            if (log.isDebugEnabled()) {
                log.debug("CIBA auth code has expired.");
            }
            return true;
        }
        
        return false;
    }

    /**
     * Builds an error response redirecting to the error page.
     *
     * @param errorKey Error key for display
     * @return Response redirecting to error page
     * @throws URLBuilderException If URL building fails
     * @throws URISyntaxException  If URI parsing fails
     */
    private Response buildErrorResponse(String errorKey) throws URLBuilderException, URISyntaxException {

        String errorUrl = ServiceURLBuilder.create()
                .addPath(CibaConstants.CIBA_SUCCESS_ENDPOINT_PATH)
                .addParameter(ERROR, errorKey)
                .build()
                .getAbsolutePublicURL();
        return Response.status(HttpServletResponse.SC_FOUND).location(new URI(errorUrl)).build();
    }

    private Response handleCibaCoreException(CibaCoreException e) throws OAuthSystemException {

        log.error("Error occurred while processing CIBA authentication request.", e);
        OAuthResponse oAuthResponse = OAuthASResponse
                .errorResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR)
                .setError(OAuth2ErrorCodes.SERVER_ERROR)
                .setErrorDescription("Internal Server Error")
                .buildJSONMessage();
        return Response.status(oAuthResponse.getResponseStatus())
                .header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE, EndpointUtil.getRealmInfo())
                .entity(oAuthResponse.getBody())
                .build();
    }

    private Response handleURLBuilderException(URLBuilderException e) throws OAuthSystemException {

        log.error("Error occurred while building URL for CIBA authentication.", e);
        OAuthResponse oAuthResponse = OAuthASResponse
                .errorResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR)
                .setError(OAuth2ErrorCodes.SERVER_ERROR)
                .setErrorDescription("Internal Server Error")
                .buildJSONMessage();
        return Response.status(oAuthResponse.getResponseStatus())
                .header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE, EndpointUtil.getRealmInfo())
                .entity(oAuthResponse.getBody())
                .build();
    }

    private Response handleURISyntaxException(URISyntaxException e) throws OAuthSystemException {

        log.error("Error while parsing URI for CIBA authentication.", e);
        OAuthResponse oAuthResponse = OAuthASResponse
                .errorResponse(HttpServletResponse.SC_INTERNAL_SERVER_ERROR)
                .setError(OAuth2ErrorCodes.SERVER_ERROR)
                .setErrorDescription("Internal Server Error")
                .buildJSONMessage();
        return Response.status(oAuthResponse.getResponseStatus())
                .header(OAuthConstants.HTTP_RESP_HEADER_AUTHENTICATE, EndpointUtil.getRealmInfo())
                .entity(oAuthResponse.getBody())
                .build();
    }
}
