/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.glite.authz.pep.server;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.Security;
import java.util.List;
import java.util.Timer;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Status;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.http.JettyAdminService;
import org.glite.authz.common.http.JettyRunThread;
import org.glite.authz.common.http.JettyShutdownTask;
import org.glite.authz.common.http.JettySslSelectChannelConnector;
import org.glite.authz.common.http.StatusCommand;
import org.glite.authz.common.http.TimerShutdownTask;
import org.glite.authz.common.logging.AccessLoggingFilter;
import org.glite.authz.common.logging.LoggingReloadTask;
import org.glite.authz.common.util.Files;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.glite.authz.pep.server.config.PEPDaemonConfiguration;
import org.glite.authz.pep.server.config.PEPDaemonIniConfigurationParser;
import org.mortbay.jetty.Connector;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.nio.SelectChannelConnector;
import org.mortbay.jetty.servlet.Context;
import org.mortbay.jetty.servlet.FilterHolder;
import org.mortbay.jetty.servlet.ServletHolder;
import org.mortbay.thread.concurrent.ThreadPool;
import org.opensaml.DefaultBootstrap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The daemon component for the PEP.
 * 
 * The daemon listens for either HTTP GET or POST requests. When receiving an HTTP GET request it expects request to be
 * a Base64 encoded value bound to the 'request' URL parameter. When receiving an HTTP POST request it expects the
 * request to be the body of the message in a Base64 encoded form. In both cases the message is the Hessian2 serialized
 * form of a {@link org.glite.authz.pep.model.Request} object and the response is a Hessian2 serialized
 * {@link org.glite.authz.pep.model.Response}.
 */
public final class PEPDaemon {

    /** System property name PDP_HOME path is bound to. */
    public static final String PEP_HOME_PROP = "org.glite.authz.pep.home";

    /** Default logging configuration refresh period: {@value} ms */
    public static final int DEFAULT_LOGGING_CONFIG_REFRESH_PERIOD = 5 * 60 * 1000;
    
    /** Class logger. */
    private static final Logger LOG = LoggerFactory.getLogger(PEPDaemon.class);

    /** Constructor. */
    private PEPDaemon() {
    }

    /**
     * Entry point for starting the daemon.
     * 
     * @param args command line arguments
     * 
     * @throws Exception thrown if there is a problem starting the daemon
     */
    public static void main(String[] args) throws Exception {
        if (args.length < 1 || args.length > 1) {
            errorAndExit("Invalid configuration file", null);
        }

        final Timer backgroundTaskTimer = new Timer(true);

        initializeLogging(System.getProperty(PEP_HOME_PROP) + "/conf/logging.xml", backgroundTaskTimer);
        Security.addProvider(new BouncyCastleProvider());
        DefaultBootstrap.bootstrap();

        final PEPDaemonConfiguration daemonConfig = parseConfiguration(args[0]);

        List<PolicyInformationPoint> pips = daemonConfig.getPolicyInformationPoints();
        if (pips != null && !pips.isEmpty()) {
            for (PolicyInformationPoint pip : daemonConfig.getPolicyInformationPoints()) {
                if (pip != null) {
                    LOG.debug("Starting PIP {}", pip.getId());
                    pip.start();
                }
            }
        }

        Server pepDaemonService = createPEPDaemonService(daemonConfig);
        JettyRunThread pepDaemonServiceThread = new JettyRunThread(pepDaemonService);
        pepDaemonServiceThread.setName("PEP Deamon Service");
        pepDaemonServiceThread.start();

        JettyAdminService adminService = createAdminService(daemonConfig, backgroundTaskTimer, pepDaemonService);
        LOG.debug("Starting admin service");
        adminService.start();

        LOG.info(Version.getServiceIdentifier() + " started");
    }

    /**
     * Creates the PEP daemon service to run.
     * 
     * @param daemonConfig the configuration for the service
     * 
     * @return a configured PEP daemon server
     */
    private static Server createPEPDaemonService(PEPDaemonConfiguration daemonConfig) {
        Server httpServer = new Server();
        httpServer.setSendServerVersion(false);
        httpServer.setSendDateHeader(false);
        httpServer.setGracefulShutdown(5000);

        BlockingQueue<Runnable> requestQueue;
        if (daemonConfig.getMaxRequestQueueSize() < 1) {
            requestQueue = new LinkedBlockingQueue<Runnable>();
        } else {
            requestQueue = new ArrayBlockingQueue<Runnable>(daemonConfig.getMaxRequestQueueSize());
        }
        ThreadPool threadPool = new ThreadPool(5, daemonConfig.getMaxRequests(), 1, TimeUnit.SECONDS, requestQueue);
        httpServer.setThreadPool(threadPool);

        Connector connector = createServiceConnector(daemonConfig);
        httpServer.setConnectors(new Connector[] { connector });

        Context servletContext = new Context(httpServer, "/", false, false);
        servletContext.setDisplayName("PEP Daemon");
        servletContext.setAttribute(PEPDaemonConfiguration.BINDING_NAME, daemonConfig);

        FilterHolder accessLoggingFilter = new FilterHolder(new AccessLoggingFilter());
        servletContext.addFilter(accessLoggingFilter, "/*", Context.REQUEST);

        ServletHolder daemonRequestServlet = new ServletHolder(new PEPDaemonServlet());
        daemonRequestServlet.setName("PEP Daemon Servlet");
        servletContext.addServlet(daemonRequestServlet, "/authz");

        return httpServer;
    }

    /**
     * Builds an admin service for the PEP daemon. This admin service has the following commands registered with it:
     * 
     * <ul>
     * <li><em>shutdown</em> - shuts down the PDP daemon service and the admin service</li>
     * <li><em>status</em> - prints out a status page w/ metrics</li>
     * <li><em>expungeResponseCache</em> - expunges all the current entries in the PDP response cache</li>
     * </ul>
     * 
     * In addition, a shutdown task that will shutdown all caches is also registered.
     * 
     * @param daemonConfig PEP daemon configuration
     * @param backgroundTimer timer used for background tasks
     * @param daemonService the PEP daemon service
     * 
     * @return the admin service
     */
    private static JettyAdminService createAdminService(PEPDaemonConfiguration daemonConfig, Timer backgroundTimer,
            Server daemonService) {

        String adminHost = daemonConfig.getAdminHost();
        if(adminHost == null){
            adminHost = "127.0.0.1";
        }
        
        int adminPort = daemonConfig.getAdminPort();
        if (adminPort < 1) {
            adminPort = 8155;
        }

        JettyAdminService adminService = new JettyAdminService(adminHost, adminPort, daemonConfig.getAdminPassword());

        adminService.registerAdminCommand(new StatusCommand(daemonConfig.getServiceMetrics()));
        adminService.registerAdminCommand(new ClearResponseCacheCommand());

        adminService.registerShutdownTask(new TimerShutdownTask(backgroundTimer));
        adminService.registerShutdownTask(new JettyShutdownTask(daemonService));
        adminService.registerShutdownTask(new Runnable() {
            public void run() {
                CacheManager cacheMgr = CacheManager.getInstance();
                if (cacheMgr != null && cacheMgr.getStatus() == Status.STATUS_ALIVE) {
                    cacheMgr.shutdown();
                }
            }
        });

        return adminService;
    }

    /**
     * Creates the HTTP connector used to receive authorization requests.
     * 
     * @param daemonConfig the daemon configuration
     * 
     * @return the created connector
     */
    private static Connector createServiceConnector(PEPDaemonConfiguration daemonConfig) {
        Connector connector;
        if (!daemonConfig.isSslEnabled()) {
            connector = new SelectChannelConnector();
        } else {
            if (daemonConfig.getKeyManager() == null) {
                LOG
                        .error("Service port was meant to be SSL enabled but no service key/certificate was specified in the configuration file");
            }
            if (daemonConfig.getTrustManager() == null) {
                LOG
                        .error("Service port was meant to be SSL enabled but no trust information directory was specified in the configuration file");
            }
            connector = new JettySslSelectChannelConnector(daemonConfig.getKeyManager(), daemonConfig.getTrustManager());
            if (daemonConfig.isClientCertAuthRequired()) {
                ((JettySslSelectChannelConnector) connector).setNeedClientAuth(true);
            }
        }
        connector.setHost(daemonConfig.getHostname());
        if (daemonConfig.getPort() == 0) {
            connector.setPort(8154);
        } else {
            connector.setPort(daemonConfig.getPort());
        }
        connector.setMaxIdleTime(daemonConfig.getConnectionTimeout());
        connector.setRequestBufferSize(daemonConfig.getReceiveBufferSize());
        connector.setResponseBufferSize(daemonConfig.getSendBufferSize());

        return connector;
    }

    /**
     * Reads the configuration file and creates a configuration from it.
     * 
     * @param configFilePath path to configuration file
     * 
     * @return configuration file and creates a configuration from it
     */
    private static PEPDaemonConfiguration parseConfiguration(String configFilePath) {
        File configFile = null;

        try {
            LOG.info("PEP Daemon configuration file: {}", configFilePath);
            configFile = Files.getReadableFile(configFilePath);
        } catch (IOException e) {
            errorAndExit(e.getMessage(), null);
        }

        try {
            PEPDaemonIniConfigurationParser configParser = new PEPDaemonIniConfigurationParser();
            return configParser.parse(new FileReader(configFile));
        } catch (IOException e) {
            LOG.error("Unable to read configuration file", e);
            errorAndExit("Unable to read configuration file " + configFilePath, e);
        } catch (ConfigurationException e) {
            LOG.error("Unable to load configuration file", e);
            errorAndExit("Error parsing configuration file " + configFilePath, e);
        }

        return null;
    }

    /**
     * Logs, as an error, the error message and exits the program.
     * 
     * @param errorMessage error message
     * @param e exception that caused it
     */
    private static void errorAndExit(String errorMessage, Exception e) {
        System.err.println(errorMessage);
        if (e != null) {
            System.err.println("This error was caused by the exception:");
            e.printStackTrace(System.err);
        }

        System.out.flush();
        System.exit(1);
    }

    /**
     * Initializes the logging system and starts the process to watch for config file changes (5 min).
     * 
     * @param loggingConfigFilePath path to the logging configuration file
     * @param reloadTasks timer controlling the reloading of tasks
     */
    private static void initializeLogging(String loggingConfigFilePath, Timer reloadTasks) {
        LoggingReloadTask reloadTask = new LoggingReloadTask(loggingConfigFilePath);
        // check/reload every 5 minutes
        reloadTask.run();
        reloadTasks.scheduleAtFixedRate(reloadTask, DEFAULT_LOGGING_CONFIG_REFRESH_PERIOD, DEFAULT_LOGGING_CONFIG_REFRESH_PERIOD);
    }
}