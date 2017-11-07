package org.wso2.carbon.identity.oidc.session;

import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

public interface LogoutTokenBuilder {

    /**
     * Returns logout token and back-channel logout uri map
     *
     * @param request
     * @return
     * @throws IdentityOAuth2Exception
     */
    public Map<String, String> buildLogoutToken(HttpServletRequest request, HttpServletResponse response)
            throws IdentityOAuth2Exception, InvalidOAuthClientException;
}

