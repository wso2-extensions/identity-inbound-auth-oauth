/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.par.dao;

import org.wso2.carbon.identity.oauth.par.cache.CacheBackedParDAO;

/**
 * Creates required ParDAO.
 */
public class ParDAOFactory {

    private final ParMgtDAO parMgtDAO;

    private ParDAOFactory() {

        parMgtDAO = new CacheBackedParDAO();
    }

    private static final ParDAOFactory parDAOFactoryInstance = new ParDAOFactory();

    /**
     * Returns parDAOFactory instance.
     *
     * @return Instance of parDAOFactory.
     */
    public static ParDAOFactory getInstance() {

        return parDAOFactoryInstance;
    }

    /**
     *  Returns instance of ParMgtDAO.
     *
     * @return Instance of ParMgtDAO.
     */
    public ParMgtDAO getParAuthMgtDAO() {

        return parMgtDAO;
    }
}
