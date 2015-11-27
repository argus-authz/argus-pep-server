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
import java.util.EnumSet;
import java.util.List;
import java.util.Timer;

import javax.servlet.DispatcherType;

import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Status;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.thread.ThreadPool;
import org.glite.authz.common.config.ConfigurationException;
import org.glite.authz.common.http.CertChainValidatorDisposeTask;
import org.glite.authz.common.http.JettyAdminService;
import org.glite.authz.common.http.JettyRunThread;
import org.glite.authz.common.http.JettyServerShutdownTask;
import org.glite.authz.common.http.ServiceMetricsServlet;
import org.glite.authz.common.http.ShutdownTask;
import org.glite.authz.common.http.StatusCommand;
import org.glite.authz.common.http.SystemExitTask;
import org.glite.authz.common.http.TimerShutdownTask;
import org.glite.authz.common.logging.AccessLoggingFilter;
import org.glite.authz.common.logging.LoggingReloadTask;
import org.glite.authz.common.util.Files;
import org.glite.authz.pep.pip.PolicyInformationPoint;
import org.glite.authz.pep.pip.PolicyInformationPointsShutdownTask;
import org.glite.authz.pep.server.config.PEPDaemonConfiguration;
import org.glite.authz.pep.server.config.PEPDaemonIniConfigurationParser;
import org.italiangrid.utils.jetty.TLSServerConnectorBuilder;
import org.italiangrid.utils.jetty.ThreadPoolBuilder;
import org.opensaml.DefaultBootstrap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.emi.security.authn.x509.X509CertChainValidatorExt;

/**
 * The daemon component for the PEP.
 * 
 * The daemon listens for either HTTP GET or POST requests. When receiving an
 * HTTP GET request it expects request to be a Base64 encoded value bound to the
 * 'request' URL parameter. When receiving an HTTP POST request it expects the
 * request to be the body of the message in a Base64 encoded form. In both cases
 * the message is the Hessian2 serialized form of a Request object and the
 * response is a Hessian2 serialized Response.
 */
public final class PEPDaemon {

  /** System property name PEPD_HOME path is bound to. */
  public static final String PEP_HOME_PROP = "org.glite.authz.pep.home";

  /** System property name PEPD_CONFDIR path is bound to. */
  public static final String PEP_CONFDIR_PROP = "org.glite.authz.pep.confdir";

  /** System property name PEPD_LOGDIR path is bound to. */
  public static final String PEP_LOGDIR_PROP = "org.glite.authz.pep.logdir";

  /** System property name PEP_GRACEFUL to set to force a graceful shutdown */
  public static final String PEP_GRACEFUL_PROP = "org.glite.authz.pep.server.graceful";

  /** Default admin port: {@value} */
  public static int DEFAULT_ADMIN_PORT = 8155;

  /** Default admin host: {@value} */
  public static String DEFAULT_ADMIN_HOST = "localhost";

  /** Default service port: {@value} */
  public static int DEFAULT_SERVICE_PORT = 8154;

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
   * @param args
   *          command line arguments
   * 
   * @throws Exception
   *           thrown if there is a problem starting the daemon
   */
  public static void main(String[] args) throws Exception {
    
    // Tell OpenSAML that it should not mess with our 
    // HttpClient hostname verification configuration
    System.setProperty(
      DefaultBootstrap.SYSPROP_HTTPCLIENT_HTTPS_DISABLE_HOSTNAME_VERIFICATION,
      "true");

    if (args.length < 1 || args.length > 1) {
      errorAndExit("Missing configuration file argument", null);
    }

    String confDir = System.getProperty(PEP_CONFDIR_PROP);
    if (confDir == null) {
      errorAndExit("System property " + PEP_CONFDIR_PROP + " is not set", null);
    }

    final Timer backgroundTaskTimer = new Timer(true);

    String loggingConfigFilePath = confDir + "/logging.xml";
    initializeLogging(loggingConfigFilePath, backgroundTaskTimer);

    Security.addProvider(new BouncyCastleProvider());
    DefaultBootstrap.bootstrap();

    final PEPDaemonConfiguration daemonConfig = parseConfiguration(args[0]);

    List<PolicyInformationPoint> pips = daemonConfig
      .getPolicyInformationPoints();
    if (pips != null && !pips.isEmpty()) {
      LOG.info("Starting all PIPs");
      for (PolicyInformationPoint pip : daemonConfig
        .getPolicyInformationPoints()) {
        if (pip != null) {
          LOG.debug("Starting PIP {}", pip.getId());
          pip.start();
        }
      }
    }

    final Server pepServer = createPEPDaemonService(daemonConfig);
    JettyRunThread pepDaemonServiceThread = new JettyRunThread(pepServer);
    pepDaemonServiceThread.setName("PEP Server Service");
    pepDaemonServiceThread.start();

    JettyAdminService adminService = createAdminService(daemonConfig,
      backgroundTaskTimer, pepServer);
    LOG.debug("Starting admin service");
    adminService.start();

    LOG.debug("Register shutdown hook");
    Runtime.getRuntime().addShutdownHook(new Thread() {

      ShutdownTask task = new JettyServerShutdownTask(pepServer);

      public void run() {

        task.run();
      }
    });

    LOG.info(Version.getServiceIdentifier() + " started");
  }

  /**
   * Creates the PEP daemon service to run.
   * 
   * @param daemonConfig
   *          the configuration for the service
   * 
   * @return a configured PEP daemon server
   */
  private static Server createPEPDaemonService(
    PEPDaemonConfiguration daemonConfig) {

    ThreadPool tp = ThreadPoolBuilder.instance().withMinThreads(5)
      .withMaxThreads(daemonConfig.getMaxRequests())
      .withMaxRequestQueueSize(daemonConfig.getMaxRequestQueueSize()).build();

    Server httpServer = new Server(tp);

    httpServer.setStopAtShutdown(true);

    // set JOPTS=-Dorg.glite.authz.pep.server.graceful to enable graceful
    // shutdown (10sec)
    if (System.getProperty(PEP_GRACEFUL_PROP) != null) {
      LOG.info("Graceful shutdown enabled: " + PEP_GRACEFUL_PROP);
      httpServer.setStopTimeout(10000); // 10 sec
    }

    httpServer.addConnector(createServiceConnector(daemonConfig, httpServer));

    ServletContextHandler servletContext = new ServletContextHandler(
      httpServer, "/", false, false);

    servletContext.setDisplayName("PEP Server");
    servletContext.setAttribute(PEPDaemonConfiguration.BINDING_NAME,
      daemonConfig);

    FilterHolder accessLoggingFilter = new FilterHolder(
      new AccessLoggingFilter());

    servletContext.addFilter(accessLoggingFilter, "/*",
      EnumSet.of(DispatcherType.REQUEST));

    ServletHolder authzRequestServlet = new ServletHolder(
      new PEPDaemonServlet());
    authzRequestServlet.setName("Authorization Servlet");
    servletContext.addServlet(authzRequestServlet, "/authz");

    ServletHolder statusRequestServlet = new ServletHolder(
      new ServiceMetricsServlet(daemonConfig.getServiceMetrics()));
    statusRequestServlet.setName("Status Servlet");
    servletContext.addServlet(statusRequestServlet, "/status");

    return httpServer;
  }

  /**
   * Builds an admin service for the PEP daemon. This admin service has the
   * following commands registered with it:
   * 
   * <ul>
   * <li><em>shutdown</em> - shuts down the PDP daemon service and the admin
   * service</li>
   * <li><em>status</em> - prints out a status page w/ metrics</li>
   * <li><em>expungeResponseCache</em> - expunges all the current entries in the
   * PDP response cache</li>
   * </ul>
   * 
   * In addition, a shutdown task that will shutdown all caches is also
   * registered.
   * 
   * @param daemonConfig
   *          PEP daemon configuration
   * @param backgroundTimer
   *          timer used for background tasks
   * @param daemonService
   *          the PEP daemon service
   * 
   * @return the admin service
   */
  private static JettyAdminService createAdminService(
    PEPDaemonConfiguration daemonConfig, Timer backgroundTimer,
    Server daemonService) {

    String adminHost = daemonConfig.getAdminHost();
    if (adminHost == null) {
      adminHost = DEFAULT_ADMIN_HOST;
    }

    int adminPort = daemonConfig.getAdminPort();
    if (adminPort < 1) {
      adminPort = DEFAULT_ADMIN_PORT;
    }

    JettyAdminService adminService = new JettyAdminService(adminHost,
      adminPort, daemonConfig.getAdminPassword());

    adminService.registerAdminCommand(new StatusCommand(daemonConfig
      .getServiceMetrics()));
    adminService.registerAdminCommand(new ClearResponseCacheCommand());

    // first shutdown task will force a System.exit(0) after 60 sec.
    adminService.registerShutdownTask(new SystemExitTask(60000));
    adminService.registerShutdownTask(new TimerShutdownTask(backgroundTimer));
    adminService
      .registerShutdownTask(new JettyServerShutdownTask(daemonService));
    // shutdown the cache
    adminService.registerShutdownTask(new ShutdownTask() {

      public void run() {

        CacheManager cacheMgr = CacheManager.getInstance();
        if (cacheMgr != null && cacheMgr.getStatus() == Status.STATUS_ALIVE) {
          cacheMgr.shutdown();
        }
      }
    });
    // shutdown the PIPs
    adminService.registerShutdownTask(new PolicyInformationPointsShutdownTask(
      daemonConfig.getPolicyInformationPoints()));

    // dispose the cert chain validator
    X509CertChainValidatorExt validator = daemonConfig.getCertChainValidator();
    adminService.registerShutdownTask(new CertChainValidatorDisposeTask(
      validator));

    return adminService;
  }

  /**
   * Creates the HTTP connector used to receive authorization requests.
   * 
   * @param daemonConfig
   *          the daemon configuration
   * 
   * @return the created connector
   */
  private static ServerConnector createServiceConnector(
    PEPDaemonConfiguration daemonConfig, Server server) {

    ServerConnector connector;
    
    HttpConfiguration configuration = new HttpConfiguration();
    configuration.setOutputBufferSize(daemonConfig.getSendBufferSize());

    configuration.setSendDateHeader(false);
    configuration.setSendServerVersion(false);

    if (!daemonConfig.isSslEnabled()) {
      connector = new ServerConnector(server);
    } else {

      if (daemonConfig.getCertChainValidator() == null) {

        String errorMessage = "Service port was meant to be SSL enabled, but no"
          + " certificate chain validator was found in configuration.";

        LOG.error(errorMessage);

        throw new IllegalStateException(errorMessage);
      }

      TLSServerConnectorBuilder builder = TLSServerConnectorBuilder.instance(
        server, daemonConfig.getCertChainValidator());

      builder.withNeedClientAuth(daemonConfig.isClientCertAuthRequired());
      
      builder.withKeyManager(daemonConfig.getKeyManager());
      
      builder.httpConfiguration().setOutputBufferSize(
        daemonConfig.getSendBufferSize());

      builder.httpConfiguration().setSendDateHeader(false);
      builder.httpConfiguration().setSendServerVersion(false);

      connector = builder.build();
    }

    connector.setHost(daemonConfig.getHostname());

    if (daemonConfig.getPort() == 0) {
      connector.setPort(DEFAULT_SERVICE_PORT);
    } else {
      connector.setPort(daemonConfig.getPort());
    }

    connector.setIdleTimeout(daemonConfig.getConnectionTimeout());

    return connector;
  }

  /**
   * Reads the configuration file and creates a configuration from it.
   * 
   * @param configFilePath
   *          path to configuration file
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
   * @param errorMessage
   *          error message
   * @param e
   *          exception that caused it
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
   * Initializes the logging system and starts the process to watch for config
   * file changes (5 min).
   * <p>
   * The function uses {@link #errorAndExit(String, Exception)} if the
   * loggingConfigFilePath is a directory, does not exist, or can not be read
   * 
   * @param loggingConfigFilePath
   *          path to the logging configuration file
   * @param reloadTasks
   *          timer controlling the reloading of tasks
   */
  private static void initializeLogging(String loggingConfigFilePath,
    Timer reloadTasks) {

    LoggingReloadTask reloadTask = null;
    try {
      reloadTask = new LoggingReloadTask(loggingConfigFilePath);
    } catch (IOException e) {
      errorAndExit("Invalid logging configuration file: "
        + loggingConfigFilePath, e);
    }
    // check/reload every 5 minutes
    reloadTask.run();
    reloadTasks.scheduleAtFixedRate(reloadTask,
      DEFAULT_LOGGING_CONFIG_REFRESH_PERIOD,
      DEFAULT_LOGGING_CONFIG_REFRESH_PERIOD);
  }
}
