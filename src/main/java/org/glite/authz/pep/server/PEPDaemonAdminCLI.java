/*
 * Copyright 2009 EGEE Collaboration
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

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.glite.authz.common.http.NoTrustTrustManager;
import org.glite.authz.common.util.Strings;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.TLSProtocolSocketFactory;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;

/**
 * A simple PDP daemon administration client. This client is capable of outputting the status page and shutting down the
 * daemon.
 */
public class PEPDaemonAdminCLI {

    /**
     * Run's the admin client.
     * 
     * @param args command line arguments
     */
    public static void main(String[] args) {
        if (args.length == 0) {
            errorAndExit("Invalid command line arguments");
        }

        LoggerContext lc = (LoggerContext) LoggerFactory.getILoggerFactory();
        Logger rootLogger = lc.getLogger(LoggerContext.ROOT_NAME);
        rootLogger.setLevel(Level.OFF);

        String host = null;
        try{
            InetAddress[] addresses;
            if(args.length == 1){
                addresses = InetAddress.getAllByName(null);
            }else{
                addresses = InetAddress.getAllByName(args[1]);
            }
            host = addresses[0].getHostName();
        }catch(UnknownHostException e){
            errorAndExit("The host " + args[1] + " is not a valid hostname or IP address");
        }
        
        if (Strings.safeEquals(args[0], "status")) {
            doStat(host, Integer.parseInt(args[2]), Boolean.parseBoolean(args[3]));
        } else if (Strings.safeEquals(args[0], "shutdown")) {
            doShutdown(host, Integer.parseInt(args[2]));
        } else {
            errorAndExit("Invalid command");
        }
    }

    /**
     * Connects to the service port and get the status of the service.
     * 
     * @param host host to connect to
     * @param port port to connect to
     * @param sslEnabled whether the status port is running on SSL or not
     */
    private static void doStat(String host, int port, boolean sslEnabled) {
        String scheme = sslEnabled ? "https" : "http";
        GetMethod statCommand = new GetMethod(scheme + "://" + host + ":" + port + "/status");
        executeCommand(statCommand, host, port);

        try {
            System.out.println(statCommand.getResponseBodyAsString());
        } catch (IOException e) {
            errorAndExit("Unable to read status response from service");
        }
    }

    /**
     * Connects to the shutdown port and shuts the service down.
     * 
     * @param host host to connect to
     * @param port port to connect to
     */
    private static void doShutdown(String host, int port) {

        GetMethod shutdownCommand = new GetMethod("http://" + host + ":" + port + "/shutdown");
        executeCommand(shutdownCommand, host, port);
        System.out.println("PEP Daemon shutdown");
    }

    /**
     * Executes the service command. Also checks to ensure the HTTP return code was 200.
     * 
     * @param command the command
     * @param host host to connect to
     * @param port port to connect to
     */
    private static void executeCommand(GetMethod command, String host, int port) {
        HttpClientBuilder clientBuilder = new HttpClientBuilder();
        clientBuilder.setHttpsProtocolSocketFactory(new TLSProtocolSocketFactory(null, new NoTrustTrustManager()));
        HttpClient httpClient = clientBuilder.buildClient();

        try {
            httpClient.executeMethod(command);
        } catch (ConnectException e) {
            errorAndExit("Unable to connect to " + host + ":" + port +", perhaps the service is not running");
        } catch (IOException e) {
            errorAndExit("Error executing service command:\n" + e.getMessage());
        }

        int statusCode = command.getStatusCode();
        if (statusCode != HttpStatus.SC_OK) {
            errorAndExit("Service returned unexpected HTTP status code; " + statusCode);
        }
    }

    /**
     * Prints the given error message to STDERR and exits with a status code of 1.
     * 
     * @param error error message to print
     */
    private static void errorAndExit(String error) {
        System.err.println(error);
        System.exit(1);
    }
}