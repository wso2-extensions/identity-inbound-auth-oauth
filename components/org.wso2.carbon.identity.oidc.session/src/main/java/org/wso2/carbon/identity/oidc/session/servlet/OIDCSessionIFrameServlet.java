/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oidc.session.servlet;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.text.StrSubstitutor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oidc.session.OIDCSessionConstants;
import org.wso2.carbon.identity.oidc.session.OIDCSessionManagerException;
import org.wso2.carbon.identity.oidc.session.util.OIDCSessionManagementUtil;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OIDCSessionIFrameServlet extends HttpServlet {

    private static final Log log = LogFactory.getLog(OIDCSessionIFrameServlet.class);

    private static final String CLIENT_ORIGIN_PLACE_HOLDER = "CLIENT_ORIGIN";
    private static final String ERROR_RESPONSE = "<html><body>Invalid OP IFrame Request</body></html>";

    private static final String OP_IFRAME_RESOURCE = "op_iframe.html";

    private static StringBuilder opIFrame = null;

    @Override
    public void init() throws ServletException {
        loadOPIFrame();
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("text/html");

        String clientId = request.getParameter(OIDCSessionConstants.OIDC_CLIENT_ID_PARAM);

        try {
            if (StringUtils.isBlank(clientId)) {
                throw new OIDCSessionManagerException(
                        "Invalid request. client_id not found in request as parameter.");
            }
            String callbackURL = getCallbackURL(request, clientId);
            String clientOrigin = OIDCSessionManagementUtil.getOrigin(callbackURL);

            if (log.isDebugEnabled()) {
                log.debug("Client Origin : " + clientOrigin);
            }
            response.getWriter().print(getOPIFrame(clientOrigin));
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            log.error("Error while retrieving OAuth application information for the provided client id : " + clientId +
                      ", " +  e.getMessage());
            if(log.isDebugEnabled()){
                log.debug(e);
            }
            response.getWriter().print(ERROR_RESPONSE);
        } catch (OIDCSessionManagerException e) {
            log.error(e.getMessage(), e);
            response.getWriter().print(ERROR_RESPONSE);
        }
    }

    private String getCallbackURL(HttpServletRequest request, String clientId)
            throws InvalidOAuthClientException, IdentityOAuth2Exception, OIDCSessionManagerException {

        OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
        OAuthAppDO oAuthAppDO = oAuthAppDAO.getAppInformation(clientId);
        String configuredCallbackURL = oAuthAppDO.getCallbackUrl();
        if (log.isDebugEnabled()) {
            log.debug("Requested client_id : " + clientId + " Configured callbackUrl : " + configuredCallbackURL);
        }
        if (StringUtils.isBlank(configuredCallbackURL)) {
            throw new OIDCSessionManagerException(
                    "CallbackURL is empty in service provider configuration, clientId : " + clientId);
        }
        if (configuredCallbackURL.startsWith(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX)) {
            if (log.isDebugEnabled()) {
                log.debug("Regex value found for callback url in service provider.");
            }
            String rpIFrameReqCallbackURL = request.getParameter(OIDCSessionConstants.OIDC_REDIRECT_URI_PARAM);
            if (StringUtils.isBlank(rpIFrameReqCallbackURL)) {
                throw new OIDCSessionManagerException(
                        "Invalid request. redirect_uri not found in request as parameter. It is "
                        + "mandatory because of there is regex pattern for "
                        + "callback url in service provider configuration. client_id : " + clientId);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Requested redirect_uri from rp IFrame : " + rpIFrameReqCallbackURL);
                }
                String regexp = configuredCallbackURL
                        .substring(OAuthConstants.CALLBACK_URL_REGEXP_PREFIX.length());
                if (rpIFrameReqCallbackURL.matches(regexp)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Requested redirect_uri is matched with the regex in service provider.");
                    }
                    configuredCallbackURL = rpIFrameReqCallbackURL;
                } else {
                    throw new OIDCSessionManagerException(
                            "Invalid request. redirect_uri is not matched with the regex that is "
                            + "configured in the service provider, client_id : " + clientId);
                }
            }
        }
        return configuredCallbackURL;
    }

    private String getOPIFrame(String clientOrigin) {
        Map<String, Object> valuesMap = new HashMap<>();
        valuesMap.put(CLIENT_ORIGIN_PLACE_HOLDER, clientOrigin);

        StrSubstitutor substitutor = new StrSubstitutor(valuesMap);
        return substitutor.replace(opIFrame.toString());
    }

    private void loadOPIFrame() {

        opIFrame = new StringBuilder();
        Path opIframeHtmlPath = Paths
                .get(CarbonUtils.getCarbonHome(), "repository", "resources", "identity", "pages", "op_iframe.html");

        if (Files.exists(opIframeHtmlPath)) {
            try (InputStream inputStream = Files.newInputStream(opIframeHtmlPath)) {
                int i;
                while ((i = inputStream.read()) > 0) {
                    opIFrame.append((char) i);
                }
            } catch (IOException e) {
                log.error("Failed to load OP IFrame", e);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Failed to load OP IFrame from external directory path: " + opIframeHtmlPath);
            }
            try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(OP_IFRAME_RESOURCE)) {
                int i;
                while ((i = inputStream.read()) > 0) {
                    opIFrame.append((char) i);
                }
            } catch (IOException e) {
                log.error("Failed to load OP IFrame", e);
            }
        }
    }
}
