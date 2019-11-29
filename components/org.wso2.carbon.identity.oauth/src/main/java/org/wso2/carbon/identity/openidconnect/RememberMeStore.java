/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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
package org.wso2.carbon.identity.openidconnect;

import org.apache.commons.collections.map.HashedMap;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Calendar;
import java.util.Map;

/**
 * Remember me store.
 */
public class RememberMeStore {

    private static RememberMeStore store = new RememberMeStore();
    private static Log log = LogFactory.getLog(RememberMeStore.class);
    private Map<String, Long> rememberMeMap = new HashedMap();

    private RememberMeStore() {

    }

    public static synchronized RememberMeStore getInstance() {
        return store;
    }

    /**
     * Adds the user to the store
     *
     * @param username
     */
    public synchronized void addUserToStore(String username) {
        long timestamp = Calendar.getInstance().getTimeInMillis();
        rememberMeMap.put(username, timestamp);
    }

    /**
     * Check if the user authenticated
     *
     * @param username
     * @return
     */
    public synchronized boolean isUserInStore(String username) {
        if (rememberMeMap.containsKey(username)) {
            long timestamp = rememberMeMap.get(username);
            long curtime = Calendar.getInstance().getTimeInMillis();
            if (curtime - timestamp > 1200000) { // after 20 mins invalidates
                log.warn("RememberMe session expired. Please login");
                return false;
            }
            return true;
        }
        return false;
    }

}
