/*
 *Copyright (c) 2005-2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *WSO2 Inc. licenses this file to you under the Apache License,
 *Version 2.0 (the "License"); you may not use this file except
 *in compliance with the License.
 *You may obtain a copy of the License at
 *
 *http://www.apache.org/licenses/LICENSE-2.0
 *
 *Unless required by applicable law or agreed to in writing,
 *software distributed under the License is distributed on an
 *"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *KIND, either express or implied.  See the License for the
 *specific language governing permissions and limitations
 *under the License.
 */

package org.wso2.carbon.identity.oauth.ui;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.stub.OAuthServiceAuthenticationException;
import org.wso2.carbon.identity.oauth.stub.types.Parameters;
import org.wso2.carbon.identity.oauth.ui.client.OAuthServiceClient;
import org.wso2.carbon.identity.oauth.ui.internal.OAuthUIServiceComponentHolder;
import org.wso2.carbon.ui.CarbonUIUtil;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLDecoder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet class for OAuth.
 */
public class OAuthServlet extends HttpServlet {

    /**
     *
     */
    private static final long serialVersionUID = -7309826651165509449L;

    private static final Log log = LogFactory.getLog(OAuthServlet.class);

    /*
     * (non-Javadoc)
     *
     * @see javax.servlet.http.HttpServlet#service(javax.servlet.http.HttpServletRequest,
     * javax.servlet.http.HttpServletResponse)
     */
    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        String requestType = req.getPathInfo();
        Parameters params = populateOauthConsumerData(req);
        Parameters token = null;
        String oauthToken = null;
        String oauthTokenSecret = null;
        String oauthCallbackConfirmed = null;

        try {
            String backendServerURL = CarbonUIUtil
                    .getServerURL(OAuthUIServiceComponentHolder.getInstance().getServerConfigurationService());
            ConfigurationContext configContext =
                    OAuthUIServiceComponentHolder.getInstance().getConfigurationContextService()
                            .getServerConfigContext();
            OAuthServiceClient client = new OAuthServiceClient(backendServerURL, configContext);

            if (requestType.indexOf(OAuthConstants.OAuth10AEndpoints.REQUEST_TOKEN_URL) > -1) {
                // To obtain a Request Token, the Consumer sends an HTTP request to the Service
                // Provider's Request Token URL. The Service Provider documentation specifies the
                // HTTP method for this request, and HTTP POST is RECOMMENDED.The Service Provider
                // verifies the signature and Consumer Key. If successful, it generates a Request
                // Token and Token Secret and returns them to the Consumer in the HTTP response body
                // as defined in Service Provider Response Parameters. The Service Provider MUST
                // ensure the Request Token cannot be exchanged for an Access Token until the User
                // successfully grants access in Obtaining User Authorization.
                String reqToken = null;
                PrintWriter out = resp.getWriter();
                token = client.getOauthRequestToken(params);
                oauthToken = token.getOauthToken();
                oauthTokenSecret = token.getOauthTokenSecret();
                oauthCallbackConfirmed = "true";
                reqToken = OAuthConstants.OAUTH_TOKEN + "=" + Encode.forUriComponent(oauthToken) + "&"
                        + OAuthConstants.OAUTH_TOKEN_SECRET + "=" + Encode.forUriComponent(oauthTokenSecret) + "&"
                        + OAuthConstants.OAUTH_CALLBACK_CONFIRMED + "=" +
                        Encode.forUriComponent(oauthCallbackConfirmed);
                out.write(reqToken);
                out.close();
                resp.setStatus(200);
            } else if (requestType.indexOf(OAuthConstants.OAuth10AEndpoints.AUTHORIZE_TOKEN_URL) > -1) {
                // In order for the Consumer to be able to exchange the Request Token for an Access
                // Token, the Consumer MUST obtain approval from the User by directing the User to
                // the Service Provider. The Consumer constructs an HTTP GET request to the Service
                // Provider's User Authorization URL.
                String userName = req.getParameter("oauth_user_name");
                String password = req.getParameter("oauth_user_password");
                String tokenFromSession = (String) req.getSession().getAttribute("oauth_req_token");
                if (userName == null || password == null || tokenFromSession == null) {
                    Parameters metadata = client.getScope(params.getOauthToken());
                    req.getSession().setAttribute("oauth_req_token", params.getOauthToken());
                    req.getSession().setAttribute("oauth_scope", metadata.getScope());
                    req.getSession().setAttribute("oauth_app_name", metadata.getAppName());
                    resp.sendRedirect(IdentityUtil.getServerURL("/carbon/oauth/oauth-login.jsp", false, true));
                }
            } else if (requestType.indexOf(OAuthConstants.OAuth10AEndpoints.ACCESS_TOKEN_URL) > -1) {
                // The Request Token and Token Secret MUST be exchanged for an Access Token and
                // Token Secret.
                // To request an Access Token, the Consumer makes an HTTP request to the Service
                // Provider's Access Token URL. The Service Provider documentation specifies the
                // HTTP method for this request, and HTTP POST is RECOMMENDED. The request MUST be
                // signed per Signing Requests.
                String accessToken = null;
                PrintWriter out = resp.getWriter();
                token = client.getAccessToken(params);
                accessToken = OAuthConstants.OAUTH_TOKEN + "=" + Encode.forUriComponent(token.getOauthToken()) + "&"
                        + OAuthConstants.OAUTH_TOKEN_SECRET + "=" + Encode.forUriComponent(token.getOauthTokenSecret());
                out.write(accessToken);
                out.close();
                resp.setStatus(200);
            }
        } catch (OAuthServiceAuthenticationException e) {
            log.debug(e);
            resp.setStatus(401);
            resp.setHeader("WWW-Authenticate", "Basic realm=\"WSO2 IS\"");
        } catch (Exception e) {
            log.error(e);
            resp.setStatus(400);
        }
    }

    /*
     * Populates the Parameters object from the OAuth authorization header or query string.
     */
    private Parameters populateOauthConsumerData(HttpServletRequest request) {

        String authHeader = null;
        Parameters params = null;
        String splitChar = ",";
        boolean noAuthorizationHeader = false;

        authHeader = request.getHeader("Authorization");
        params = new Parameters();

        if (authHeader == null) {
            noAuthorizationHeader = true;
            // No Authorization header available.
            authHeader = request.getQueryString();
            splitChar = "&";
        }

        StringBuilder nonAuthParams = new StringBuilder();

        if (authHeader != null) {
            if (authHeader.startsWith("OAuth ") || authHeader.startsWith("oauth ")) {
                authHeader = authHeader.substring(authHeader.indexOf("o"));
            }
            String[] headers = authHeader.split(splitChar);
            if (headers != null && headers.length > 0) {
                for (int i = 0; i < headers.length; i++) {
                    String[] elements = headers[i].split("=");
                    if (elements != null && elements.length > 0) {
                        if (OAuthConstants.OAuth10AParams.OAUTH_CONSUMER_KEY.equals(elements[0].trim())) {
                            params.setOauthConsumerKey(removeLeadingAndTrailingQuatation(elements[1]
                                    .trim()));
                        } else if (OAuthConstants.OAuth10AParams.OAUTH_NONCE.equals(elements[0].trim())) {
                            params.setOauthNonce(removeLeadingAndTrailingQuatation(elements[1]
                                    .trim()));
                        } else if (OAuthConstants.OAuth10AParams.OAUTH_SIGNATURE.equals(elements[0].trim())) {
                            params.setOauthSignature(removeLeadingAndTrailingQuatation(elements[1]
                                    .trim()));
                        } else if (OAuthConstants.OAuth10AParams.OAUTH_SIGNATURE_METHOD.equals(elements[0].trim())) {
                            params.setOauthSignatureMethod(removeLeadingAndTrailingQuatation(elements[1]
                                    .trim()));
                        } else if (OAuthConstants.OAuth10AParams.OAUTH_TIMESTAMP.equals(elements[0].trim())) {
                            params.setOauthTimeStamp(removeLeadingAndTrailingQuatation(elements[1]
                                    .trim()));
                        } else if (OAuthConstants.OAuth10AParams.OAUTH_CALLBACK.equals(elements[0].trim())) {
                            params.setOauthCallback(removeLeadingAndTrailingQuatation(elements[1]
                                    .trim()));
                        } else if (OAuthConstants.OAuth10AParams.SCOPE.equals(elements[0].trim())) {
                            params.setScope(removeLeadingAndTrailingQuatation(elements[1].trim()));
                        } else if (OAuthConstants.OAuth10AParams.OAUTH_DISPLAY_NAME.equals(elements[0].trim())) {
                            params.setDisplayName(removeLeadingAndTrailingQuatation(elements[1]
                                    .trim()));
                        } else if (OAuthConstants.OAUTH_TOKEN.equals(elements[0].trim())) {
                            params.setOauthToken(removeLeadingAndTrailingQuatation(elements[1]
                                    .trim()));
                        } else if (OAuthConstants.OAUTH_VERIFIER.equals(elements[0].trim())) {
                            params.setOauthTokenVerifier(removeLeadingAndTrailingQuatation(elements[1]
                                    .trim()));
                        } else if (OAuthConstants.OAUTH_TOKEN_SECRET.equals(elements[0].trim())) {
                            params.setOauthTokenSecret(removeLeadingAndTrailingQuatation(elements[1]
                                    .trim()));
                        } else if (OAuthConstants.OAuth10AParams.OAUTH_VERSION.equals(elements[0].trim())) {
                            params.setVersion(removeLeadingAndTrailingQuatation(elements[1].trim()));
                        } else {
                            nonAuthParams.append(elements[0].trim() + "="
                                    + removeLeadingAndTrailingQuatation(elements[1].trim()) + "&");
                        }
                    }
                }
            }
        }

        String nonOauthParamStr = nonAuthParams.toString();

        if (!noAuthorizationHeader) {
            nonOauthParamStr = request.getQueryString() + "&";
        }

        String scope = request.getParameter(OAuthConstants.OAuth10AParams.SCOPE);

        if (scope != null) {
            params.setScope(scope);
        }
        params.setHttpMethod(request.getMethod());
        if (nonOauthParamStr.length() > 1) {
            params.setBaseString(request.getRequestURL().toString() + "?"
                    + nonOauthParamStr.substring(0, nonOauthParamStr.length() - 1));
        } else {
            params.setBaseString(request.getRequestURL().toString());

        }

        return params;
    }

    private String removeLeadingAndTrailingQuatation(String base) {

        String result = base;

        if (base.startsWith("\"") || base.endsWith("\"")) {
            result = base.replace("\"", "");
        }
        result = URLDecoder.decode(result);
        return result.trim();
    }
}
