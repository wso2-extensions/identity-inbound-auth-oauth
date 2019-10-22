package org.wso2.carbon.identity.oauth2.device.errorcodes;

public class DeviceErrorCodes {

    public static final String UNAUTHORIZED_CLIENT = "unauthorized client";
    public static final String INVALID_REQUEST = "invalid request";

    public DeviceErrorCodes() {

    }

    public class SubDeviceErrorCodes {

        public static final String SLOW_DOWN = "slow_down";
        public static final String AUTHORIZATION_PENDING = "authorization_pending";
        public static final String EXPIRED_TOKEN = "expired_token";

    }
}
