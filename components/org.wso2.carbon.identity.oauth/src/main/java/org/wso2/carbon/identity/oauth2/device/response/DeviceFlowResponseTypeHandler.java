package org.wso2.carbon.identity.oauth2.device.response;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.authz.handlers.AbstractResponseTypeHandler;
import org.wso2.carbon.identity.oauth2.device.constants.Constants;
import org.wso2.carbon.identity.oauth2.device.dao.DeviceFlowPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

public class DeviceFlowResponseTypeHandler extends AbstractResponseTypeHandler {

    private static Log log = LogFactory.getLog(DeviceFlowResponseTypeHandler.class);
//    private DeviceFlowPersistenceFactory deviceFlowPersistenceFactory = new DeviceFlowPersistenceFactory();

    private String AppName;
    private String appName;

    public DeviceFlowResponseTypeHandler() {

    }

    public OAuth2AuthorizeRespDTO issue(OAuthAuthzReqMessageContext oauthAuthzMsgCtx) throws IdentityOAuth2Exception {

        OAuth2AuthorizeRespDTO respDTO = new OAuth2AuthorizeRespDTO();
        OAuth2AuthorizeReqDTO authzReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        OAuth2AuthorizeReqDTO authorizationReqDTO = oauthAuthzMsgCtx.getAuthorizationReqDTO();
        String clientId = authzReqDTO.getConsumerKey();
        String authenticatedUser = authzReqDTO.getUser().getUserName();
        OAuthAppDO oAuthAppDO = null;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
            appName = oAuthAppDO.getApplicationName();
            setAppName(appName);
        } catch (InvalidOAuthClientException e) {
            e.printStackTrace();
        }

        String UserCode = authzReqDTO.getNonce();
        log.info(UserCode);
        DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().setAuthzUser(UserCode, authenticatedUser);
        DeviceFlowPersistenceFactory.getInstance().getDeviceFlowDAO().setUserAuthenticated(UserCode,
                Constants.AUTHORIZED);
        respDTO.setCallbackURI(IdentityUtil.getServerURL("/authenticationendpoint/device_success.do?app_name=" +
                appName, false, false));

        return respDTO;
    }

    public String getAppName() {

        return AppName;
    }

    private void setAppName(String appName) {

        AppName = appName;
    }
}

