package org.wso2.carbon.identity.oauth.extension.functions;

import java.util.Map;

@FunctionalInterface
public interface CallChoreoFunction {

    /**
     * Sends data to Choreo and get the response from the Choreo service.
     * The payload and the return value from the Choreo are both JSON structure, which needs to be the contract between
     * the service and authentication script
     *
     * @param connectionMetaData Metadata to call the endpoint. This connectionMetaData map consists with connection url
     *                          (connectionMetaData.url) and api-key (connectionMetaData.apikey)
     * @param payloadData        payload data.
     * @param eventHandlers      event handlers.
     */
    void callChoreo(Map<String, String> connectionMetaData, Map<String, Object> payloadData,
                    Map<String, Object> eventHandlers);
}
