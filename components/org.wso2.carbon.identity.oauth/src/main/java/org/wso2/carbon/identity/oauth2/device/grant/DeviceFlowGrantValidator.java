package org.wso2.carbon.identity.oauth2.device.grant;

import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.validators.AbstractValidator;

import javax.servlet.http.HttpServletRequest;

public class DeviceFlowGrantValidator extends AbstractValidator<HttpServletRequest> {

    public DeviceFlowGrantValidator() {

        // device code must be in the request parameter
        requiredParams.add(OAuth.OAUTH_GRANT_TYPE);
    }
}
