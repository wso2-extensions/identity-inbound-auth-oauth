/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.identity.oauth.cache;

import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import java.util.List;

/**
 * @deprecated use {@link OAuthAppDO} to retrieve the audience. Then no need to consider caching for audience.
 */
@Deprecated
public class OIDCAudienceCacheEntry extends CacheEntry {

    private static final long serialVersionUID = -2349362862326623526L;
    private List<String> audiences;

    public List<String> getAudiences() {

        return audiences;
    }

    public void setAudiences(List<String> audiences) {

        this.audiences = audiences;
    }
}
