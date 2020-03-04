// Copyright 2020 Google LLC
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.cloud.broker.hadoop.fs;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.stub.MetadataUtils;
import com.google.common.io.BaseEncoding;
import org.ietf.jgss.GSSException;
import org.apache.hadoop.conf.Configuration;

// Classes dynamically generated by protobuf-maven-plugin:
import com.google.cloud.broker.apps.brokerserver.protobuf.BrokerGrpc;


final class BrokerGateway {

    private BrokerGrpc.BrokerBlockingStub stub;
    private ManagedChannel managedChannel;
    private Configuration config;

    private static final String CONFIG_URI = "gcp.token.broker.uri";
    private static final String CONFIG_PRINCIPAL = "gcp.token.broker.kerberos.principal";
    private static final String CONFIG_CERTIFICATE = "gcp.token.broker.tls.certificate";
    private static final String CONFIG_CERTIFICATE_PATH = "gcp.token.broker.tls.certificate.path";


    BrokerGateway(Configuration config) {
        this(config,null);
    }

    BrokerGateway(Configuration config, String sessionToken) {
        this.config = config;

        // Extract the host and port from the URI
        String brokerUri = config.get(CONFIG_URI);
        URL url;
        try {
            url = new URL(brokerUri);
        }
        catch (MalformedURLException e) {
            throw new RuntimeException("Invalid value for property `" + CONFIG_URI + "`");
        }
        String host = url.getHost();
        int port = url.getPort();

        // Determine if TLS should be used
        boolean useTLS;
        String protocol = url.getProtocol();
        if (protocol.equals("http")) {
            useTLS = false;
        }
        else if (protocol.equals("https")) {
            useTLS = true;
        }
        else {
            throw new RuntimeException("Incorrect URI scheme `" + protocol + " ` in `" + CONFIG_URI + "` property: " + brokerUri);
        }

        String tlsCertificate = config.get(CONFIG_CERTIFICATE);
        if (tlsCertificate == null) {
            String tlsCerfiticatePath = config.get(CONFIG_CERTIFICATE_PATH);
            if (tlsCerfiticatePath != null) {
                try {
                    tlsCertificate = new String(Files.readAllBytes(Paths.get(tlsCerfiticatePath)), StandardCharsets.US_ASCII);
                } catch (IOException e) {
                    throw new RuntimeException("Error reading the TLS certificate file: " + e.getMessage());
                }
            } else {
                tlsCertificate = "";
            }
        }

        managedChannel = GrpcUtils.newManagedChannel(host, port, useTLS, tlsCertificate);
        stub = GrpcUtils.newStub(managedChannel);

        if (sessionToken != null) {
            setSessionToken(sessionToken);
        }
        else {
            try {
                setSPNEGOToken();
            } catch (GSSException e) {
                // Clean up the channel before re-throwing the exception
                managedChannel.shutdownNow();
                throw new RuntimeException(
                    "User is not logged-in with Kerberos or cannot authenticate with the broker. Kerberos error message: " + e.getMessage());
            }
        }
    }

    BrokerGrpc.BrokerBlockingStub getStub() {
        return stub;
    }

    ManagedChannel getManagedChannel() {
        return managedChannel;
    }

    private void setSPNEGOToken() throws GSSException {
        String brokerPrincipal = config.get(CONFIG_PRINCIPAL);
        String encodedToken = BaseEncoding.base64().encode(SpnegoUtils.newSPNEGOToken(brokerPrincipal));

        // Set the 'authorization' header with the SPNEGO token
        Metadata metadata = new Metadata();
        Metadata.Key<String> key = Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
        metadata.put(key, "Negotiate " + encodedToken);
        stub = MetadataUtils.attachHeaders(stub, metadata);
    }

    private void setSessionToken(String sessionToken) {
        // Set the session token in the 'authorization' header
        Metadata metadata = new Metadata();
        Metadata.Key<String> key = Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
        metadata.put(key, "BrokerSession " + sessionToken);
        stub = MetadataUtils.attachHeaders(stub, metadata);
    }

}