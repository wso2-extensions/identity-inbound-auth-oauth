package org.wso2.carbon.identity.oauth.par.dao;

/**
 * Creates required CibaDAO.
 */
public class ParDAOFactory {

    // Implementation of DAO.
    private ParMgtDAO parMgtDAOImpl;

    private ParDAOFactory() {

        // This factory creates instance of PAR DAOImplementation.
        parMgtDAOImpl = new ParMgtDAOImple();
    }

    private static ParDAOFactory parDAOFactoryInstance = new ParDAOFactory();

    public static ParDAOFactory getInstance() {

        return parDAOFactoryInstance;
    }

    /**
     * @return  ParMgtDAO.
     */
    public ParMgtDAO getParAuthMgtDAO() {

        return parMgtDAOImpl;
    }
}
