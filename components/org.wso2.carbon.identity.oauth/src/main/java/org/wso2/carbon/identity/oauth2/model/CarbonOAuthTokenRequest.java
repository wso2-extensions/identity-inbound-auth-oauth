/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.oauth2.model;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.as.request.OAuthTokenRequest;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;
import org.apache.oltu.oauth2.common.validators.OAuthValidator;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import javax.servlet.http.HttpServletRequest;

/**
 * CarbonOAuthTokenRequest holds all OAuth token request parameters.
 */
public class CarbonOAuthTokenRequest extends OAuthTokenRequest {

    private static Log log = LogFactory.getLog(CarbonOAuthTokenRequest.class);

    private String assertion;
    private String windows_token;
    private String tenantDomain;
    private String pkceCodeVerifier;
    private RequestParameter[] requestParameters;
    private HttpRequestHeader[] httpRequestHeaders;
    private OAuthClientAuthnContext oAuthClientAuthnContext;

    /**
     * Constructs CarbonOAuthTokenRequest from the given HttpServletRequest
     *
     * @param request an instance of HttpServletRequest that represents an OAuth token request
     * @throws OAuthSystemException
     * @throws OAuthProblemException
     */
    public CarbonOAuthTokenRequest(HttpServletRequest request) throws OAuthSystemException,
            OAuthProblemException {

        super(request);
        assertion = request.getParameter(OAuth.OAUTH_ASSERTION);
        windows_token = request.getParameter(OAuthConstants.WINDOWS_TOKEN);
        pkceCodeVerifier = request.getParameter(OAuthConstants.OAUTH_PKCE_CODE_VERIFIER);
        setClientAuthnContext(request);

        // Store all request parameters
        if (request.getParameterNames() != null) {
            List<RequestParameter> requestParameterList = new ArrayList<RequestParameter>();
            while (request.getParameterNames().hasMoreElements()) {
                String key = request.getParameterNames().nextElement();
                String value = request.getParameter(key);
                requestParameterList.add(new RequestParameter(key, value));
            }
            requestParameters =
                    requestParameterList.toArray(new RequestParameter[requestParameterList.size()]);
        }

        // Set all http headers
        Enumeration headerNames = request.getHeaderNames();
        if (headerNames != null) {
            List<HttpRequestHeader> httpHeaderList = new ArrayList<>();
            while (headerNames.hasMoreElements()) {
                String headerName = (String) headerNames.nextElement();
                // since it is possible for some headers to have multiple values let's add them all.
                Enumeration headerValues = request.getHeaders(headerName);
                List<String> headerValueList = new ArrayList<>();
                if (headerValues != null) {
                    while (headerValues.hasMoreElements()) {
                        headerValueList.add((String) headerValues.nextElement());
                    }
                }
                httpHeaderList.add(
                        new HttpRequestHeader(headerName, headerValueList.toArray(new String[headerValueList.size()])));
            }
            httpRequestHeaders = httpHeaderList.toArray(new HttpRequestHeader[httpHeaderList.size()]);
        }
    }

    /**
     * Initialize a grant type validator
     *
     * @return an instance of OAuthValidator
     * @throws OAuthProblemException
     * @throws OAuthSystemException
     */
    @Override
    protected OAuthValidator<HttpServletRequest> initValidator() throws OAuthProblemException, OAuthSystemException {

        String requestTypeValue = getParam(OAuth.OAUTH_GRANT_TYPE);
        if (OAuthUtils.isEmpty(requestTypeValue)) {
            throw OAuthUtils.handleOAuthProblemException("Missing grant_type parameter value");
        }

        Class<? extends OAuthValidator<HttpServletRequest>> clazz = OAuthServerConfiguration
                .getInstance().getSupportedGrantTypeValidators().get(requestTypeValue);

        if (clazz == null) {
            if (log.isDebugEnabled()) {
                //Do not change this log format as these logs use by external applications
                log.debug("Unsupported Grant Type : " + requestTypeValue +
                        " for client id : " + getClientId());
            }
            throw OAuthProblemException.error(OAuthError.TokenResponse.UNSUPPORTED_GRANT_TYPE)
                    .description("Unsupported grant_type value");
        }

        return OAuthUtils.instantiateClass(clazz);
    }

    /**
     * Returns the assertion
     *
     * @return assertion
     */
    public String getAssertion() {
        return assertion;
    }

    /**
     * Returns the windows token
     *
     * @return window token
     */
    public String getWindowsToken() {
        return windows_token;
    }

    /**
     * Returns tenant domain
     *
     * @return tenant domain
     */
    public String getTenantDomain() {
        return tenantDomain;
    }

    /**
     * Sets tenant domain
     *
     * @param tenantDomain tenant domain as a string
     */
    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }

    /**
     * Get all request parameters as an array of RequestParameter objects
     *
     * @return array of RequestParameter objects
     */
    public RequestParameter[] getRequestParameters() {
        return requestParameters;
    }

    /**
     * Return code_verifier String from the OAuth2 request. Note that code_verifier is expected only for
     * OAuth requests with "Authorization Code" grant type.
     *
     * @return the OAuth PKCE code_verifier parameter.
     */
    public String getPkceCodeVerifier() {
        return pkceCodeVerifier;
    }


    /**
     * Get all request headers as an array of HttpRequestHeader objects
     *
     * @return array of HttpRequestHeader objects
     */
    public HttpRequestHeader[] getHttpRequestHeaders() {
        return httpRequestHeaders;
    }

    public OAuthClientAuthnContext getoAuthClientAuthnContext() {
        return oAuthClientAuthnContext;
    }

    public void setoAuthClientAuthnContext(OAuthClientAuthnContext oAuthClientAuthnContext) {
        this.oAuthClientAuthnContext = oAuthClientAuthnContext;
    }

    private void setClientAuthnContext(HttpServletRequest request) {
        Object oauthClientAuthnContextObj = request.getAttribute(OAuthConstants.CLIENT_AUTHN_CONTEXT);
        if (oauthClientAuthnContextObj instanceof OAuthClientAuthnContext) {
            oAuthClientAuthnContext = (OAuthClientAuthnContext) oauthClientAuthnContextObj;
        } else {
            oAuthClientAuthnContext = new OAuthClientAuthnContext();
            oAuthClientAuthnContext.setAuthenticated(false);
            oAuthClientAuthnContext.setErrorMessage("Client Authentication Failed");
            oAuthClientAuthnContext.setErrorCode(OAuthError.TokenResponse.INVALID_REQUEST);
        }
    }
}
