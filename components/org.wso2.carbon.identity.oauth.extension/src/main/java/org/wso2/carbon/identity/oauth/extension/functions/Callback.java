package org.wso2.carbon.identity.oauth.extension.functions;

import java.util.Map;
@FunctionalInterface
public interface Callback {

    void accept(Map<String, Object> eventHandlers, Map<String, Object> data, String outCome);
}
