/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.par.model;

import java.io.Serializable;
import java.util.HashMap;

/**
 * Create an object with the stored attributes
 */
public class ParDataRecord implements Serializable {
    private HashMap<String, String> parameterMap;
    private long reqMade;

    public ParDataRecord(HashMap<String, String> parameterMap , long reqMade) {
        this.parameterMap = parameterMap;
        this.reqMade = reqMade;
    }

    public HashMap<String, String> getParamMap() {
        return parameterMap;
    }

    public long getReqMade() {
        return reqMade;
    }
}
