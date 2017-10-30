package org.wso2.carbon.identity.test.common.testNg;

import org.apache.commons.dbcp.BasicDataSource;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.spi.InitialContextFactory;

/**
 * Mock initial context factory to be used to supply Datasource, etc.
 */
public class MockInitialContextFactory implements InitialContextFactory {

    private static ThreadLocal<Map<String, Object>> jndiContextData = new ThreadLocal<>();
    private static Log log = LogFactory.getLog(MockInitialContextFactory.class);

    @Override
    public Context getInitialContext(Hashtable<?, ?> environment) throws NamingException {
        Context context = Mockito.mock(Context.class);
        Mockito.doAnswer(new Answer() {

            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                String name = invocationOnMock.getArgumentAt(0, String.class);
                return getDatasource(name);
            }
        }).when(context).lookup(Matchers.anyString());

        return context;
    }

    /**
     * Destroy the initial context.
     */
    public static void destroy() {
        Map<String, Object> jndiObjectsMap = jndiContextData.get();
        if (jndiObjectsMap != null) {
            for (Object object : jndiObjectsMap.entrySet()) {
                if (object instanceof BasicDataSource) {
                    try {
                        ((BasicDataSource) object).close();
                    } catch (SQLException e) {
                        //Just Ignore for now.
                    }
                }
            }
            jndiContextData.remove();
        }
    }

    private static BasicDataSource getDatasource(String name) {
        Map context = jndiContextData.get();
        if (context == null) {
            return null;
        }
        return (BasicDataSource) context.get(name);
    }

    /**
     * Closes the datasource, given the JNDI name.
     * @param name
     */
    public static void closeDatasource(String name) {
        Map context = jndiContextData.get();
        if (context == null) {
            return;
        }
        Object old = context.get(name);
        if (old instanceof BasicDataSource) {
            try {
                ((BasicDataSource) old).close();
            } catch (Exception e) {
                log.error("Error while closing the in-memory H2 Database.", e);
            }
        }
    }

    private static void addContextLookup(String name, BasicDataSource object) {
        Map context = jndiContextData.get();
        if (context == null) {
            context = new HashMap();
            jndiContextData.set(context);
        }
        Object old = context.get(name);
        if (old instanceof BasicDataSource) {
            try {
                ((BasicDataSource) old).close();
            } catch (Exception e) {
                log.error("Error while closing the in-memory H2 Database.", e);
            }
        }
        context.put(name, object);
    }

    /**
     * Initializes the datasource given JNDI name and files.
     *
     * @param datasourceName
     * @param clazz
     * @param files
     */
    public static void initializeDatasource(String datasourceName, Class clazz, String[] files) {
        Map<String, Object> jndiObjectsMap = jndiContextData.get();
        if (jndiObjectsMap != null) {
            BasicDataSource basicDataSource = (BasicDataSource) jndiObjectsMap.get(datasourceName);
            if (basicDataSource != null && !basicDataSource.isClosed()) {
                return;
            }
        }
        String basePath = clazz.getResource("/").getFile();
        BasicDataSource dataSource = createDb(datasourceName, basePath, files);
        addContextLookup(datasourceName, dataSource);
    }

    private static BasicDataSource createDb(String dbName, String basePath, String[] files) {
        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setDriverClassName("org.h2.Driver");
        dataSource.setUsername("username");
        dataSource.setPassword("password");
        dataSource.setUrl("jdbc:h2:mem:test" + dbName);
        try (Connection connection = dataSource.getConnection()) {
            for (String f : files) {
                String scriptPath = Paths.get(basePath, f).toString();
                connection.createStatement().executeUpdate("RUNSCRIPT FROM '" + scriptPath + "'");
            }
        } catch (SQLException e) {
            log.error("Error while creating the in-memory H2 Database.", e);
        }
        return dataSource;
    }
}


