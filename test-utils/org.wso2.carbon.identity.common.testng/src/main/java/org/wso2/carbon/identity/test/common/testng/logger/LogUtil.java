package org.wso2.carbon.identity.test.common.testng.logger;

import org.apache.log4j.Level;
import org.apache.log4j.LogManager;

public class LogUtil {

    private LogUtil() {
    }

    public static void configureAndAddConsoleAppender() {
        NullAppender appender = new NullAppender();
        LogManager.getRootLogger().addAppender(appender);
    }

    public static void configureLogLevel(String logLevel) {
        Level level = Level.toLevel(logLevel);
        LogManager.getRootLogger().setLevel(level);
    }
}
