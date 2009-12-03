/*
 * Copyright 2009 Members of the EGEE Collaboration.
 * See http://www.eu-egee.org/partners for details on the copyright holders. 
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
import java.util.ArrayList;
import java.util.Timer;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Status;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.glite.authz.common.AuthorizationServiceException;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.http.JettyRunThread;
import org.glite.authz.common.http.JettyShutdownCommand;
import org.glite.authz.common.http.JettyShutdownService;
import org.glite.authz.common.http.JettySslSelectChannelConnector;
import org.glite.authz.common.http.ServiceStatusServlet;
import org.glite.authz.common.logging.AccessLoggingFilter;
import org.glite.authz.common.logging.LoggingReloadTask;
import org.glite.authz.common.pip.PolicyInformationPoint;
import org.glite.authz.common.util.Files;
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
    
    /** Class logger. */
    private static final Logger log = LoggerFactory.getLogger(PEPDaemon.class);

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

        Security.addProvider(new BouncyCastleProvider());
        
        ArrayList<Runnable> shutdownCommands = new ArrayList<Runnable>();

        final Timer configFileReloadTasks = new Timer(true);
        shutdownCommands.add(new Runnable() {
            public void run() {
                configFileReloadTasks.cancel();
            }
        });
        initializeLogging(System.getProperty(PEP_HOME_PROP) + "/conf/logging.xml", configFileReloadTasks);

        DefaultBootstrap.bootstrap();

        final PEPDaemonConfiguration daemonConfig = parseConfiguration(args[0]);
        for(PolicyInformationPoint pip : daemonConfig.getPolicyInformationPoints()){
            if(pip != null){
                log.debug("Starting PIP {}", pip.getId());
                pip.start();
            }
        }

        Server pepDaemonService = createPEPDaemonService(daemonConfig);
        pepDaemonService.setGracefulShutdown(5000);
        
        JettyRunThread pepDaemonServiceThread = new JettyRunThread(pepDaemonService);
        pepDaemonServiceThread.setName("PEP Deamon Service");
        shutdownCommands.add(new JettyShutdownCommand(pepDaemonService));
        shutdownCommands.add(new Runnable(){
            public void run() {
                for(PolicyInformationPoint pip : daemonConfig.getPolicyInformationPoints()){
                    if(pip != null){
                        try{
                            log.debug("Stopping PIP {}", pip.getId());
                            pip.stop();
                        }catch(AuthorizationServiceException e){
                            log.error("Unable to stop PIP " + pip.getId());
                        }
                    }
                }
            }
        });
        
        if(daemonConfig.getMaxCachedResponses() > 0){
            shutdownCommands.add(new Runnable(){
                public void run() {
                    CacheManager cacheMgr = CacheManager.getInstance();
                    if(cacheMgr != null  && cacheMgr.getStatus() == Status.STATUS_ALIVE){
                        cacheMgr.shutdown();
                    }
                }
            });
        }

        if (daemonConfig.getShutdownPort() == 0) {
            JettyShutdownService.startJettyShutdownService(8155, shutdownCommands);
        } else {
            JettyShutdownService.startJettyShutdownService(daemonConfig.getShutdownPort(), shutdownCommands);
        }

        pepDaemonServiceThread.start();
        log.info(Version.getServiceIdentifier() + " started");
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

        ServletHolder daemonStatusServlet = new ServletHolder(new ServiceStatusServlet());
        daemonStatusServlet.setName("PEP Status Servlet");
        servletContext.addServlet(daemonStatusServlet, "/status");

        return httpServer;
    }
    
    /**
     * Creates the HTTP connector used to receive authorization requests.
     * 
     * @param daemonConfig the daemon configuration
     * 
     * @return the created connector
     */
    private static Connector createServiceConnector(PEPDaemonConfiguration daemonConfig){
        Connector connector;
        if(!daemonConfig.isSslEnabled()){
            connector = new SelectChannelConnector();
        }else{
            if(daemonConfig.getKeyManager() == null){
                log.error("Service port was meant to be SSL enabled but no service key/certificate was specified in the configuration file");
            }
            if(daemonConfig.getTrustManager() == null){
                log.error("Service port was meant to be SSL enabled but no trust information directory was specified in the configuration file");
            }
            connector = new JettySslSelectChannelConnector(daemonConfig.getKeyManager(), daemonConfig.getTrustManager());
            if(daemonConfig.isClientCertAuthRequired()){
                ((JettySslSelectChannelConnector)connector).setWantClientAuth(true);
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
            configFile = Files.getReadableFile(configFilePath);
        } catch (IOException e) {
            errorAndExit(e.getMessage(), null);
        }

        try {
            PEPDaemonIniConfigurationParser configParser = new PEPDaemonIniConfigurationParser();
            return configParser.parse(new FileReader(configFile));
        } catch (IOException e) {
            errorAndExit("Unable to read configuration file " + configFilePath, e);
        } catch (ConfigurationException e) {
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
     * Initializes the logging system and starts the process to watch for config file changes.
     * 
     * @param loggingConfigFilePath path to the logging configuration file
     * @param reloadTasks timer controlling the reloading of tasks
     */
    private static void initializeLogging(String loggingConfigFilePath, Timer reloadTasks) {
        LoggingReloadTask reloadTask = new LoggingReloadTask(loggingConfigFilePath);
        int refreshPeriod = 5 * 60 * 1000; // check/reload every 5 minutes
        reloadTask.run();
        reloadTasks.scheduleAtFixedRate(reloadTask, refreshPeriod, refreshPeriod);
    }
}