package pqtip.connection;

import com.google.protobuf.ByteString;
import pqtip.cipher_suite.prime.PrimeCipherSuite;
import pqtip.cipher_suite.symmetric.Encoder;
import pqtip.cipher_suite.symmetric.SymmetricCipherSuite;
import pqtip.definitions.Protocol;
import pqtip.definitions.ProtocolHeader;

import java.util.Arrays;
import java.util.List;

public class PQTIPConnection implements BlockingTransportConnection {
    private final BlockingTransportConnection connection;
    private Encoder encoder;

    public PQTIPConnection(BlockingTransportConnection connection) {
        this.connection = connection;
    }

    public static PQTIPConnection initializeClient(PrimeCipherSuite psuite, List<SymmetricCipherSuite> ssuites, BlockingTransportConnection con){
        try {
            var connection = new PQTIPConnection(con);
            var initMessageBuilder = Protocol.ClientInit.newBuilder();
            initMessageBuilder = psuite.initClientParams(initMessageBuilder);
            for (var suite : ssuites) {
                initMessageBuilder.addSymmetricCipherSuites(suite.cipherSuiteDescriptor());
            }
            var initMessage = initMessageBuilder.build();
            byte[] initMessageBytes = ProtocolHeader.makeMessage((byte) 1, ProtocolHeader.CLIENT_INIT, initMessage.toByteArray());
            connection.connection.send(initMessageBytes);
            var serverResponse = new ProtocolHeader(connection.connection.receive());
            // does not handle slow flow for v1
            if (serverResponse.messageCode() != ProtocolHeader.SERVER_INIT) {
                throw new RuntimeException("Unexpected message code");
            }
            if (!serverResponse.isValid()) {
                throw new RuntimeException("Message verification failed");
            }
            var params = Protocol.ServerInit.parseFrom(serverResponse.body());
            SymmetricCipherSuite symmetricCipherSuite = null;
            for (var suite : ssuites) {
                if (suite.cipherSuiteDescriptor().equals(params.getSymmetricCipherSuite())) {
                    symmetricCipherSuite = suite;
                    break;
                }
            }
            if (symmetricCipherSuite == null) {
                throw new RuntimeException("Unsopported symmetric cipher suite");
            }
            var masterKey = psuite.deriveClientMasterKey(params);
            connection.encoder = symmetricCipherSuite.fromPreMaster(masterKey);
            return connection;
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    public static PQTIPConnection initializeServer(List<PrimeCipherSuite> psuites, List<SymmetricCipherSuite> ssuites, BlockingTransportConnection con){
        try {
            var connection = new PQTIPConnection(con);
            var clientInit = new ProtocolHeader(connection.connection.receive());
            // does not handle slow flow for v1
            if (clientInit.messageCode() != ProtocolHeader.CLIENT_INIT) {
                throw new RuntimeException("Unexpected message code");
            }
            if (!clientInit.isValid()) {
                throw new RuntimeException("Message verification failed");
            }
            var initMessage = Protocol.ClientInit.parseFrom(clientInit.body());
            PrimeCipherSuite primeCipherSuite = null;
            for (var suite : psuites) {
                if (suite.cipherSuiteDescriptor().equals(initMessage.getPrimeCipherSuite())) {
                    primeCipherSuite = suite;
                    break;
                }
            }
            if (primeCipherSuite == null) {
                throw new RuntimeException("Unsopported prime cipher suite");
            }
            SymmetricCipherSuite symmetricCipherSuite = null;
            for (var suite : ssuites) {
                for(var suiteDescriptor : initMessage.getSymmetricCipherSuitesList()) {
                    if (suite.cipherSuiteDescriptor().equals(suiteDescriptor)) {
                        symmetricCipherSuite = suite;
                        break;
                    }
                }
            }
            if (symmetricCipherSuite == null) {
                throw new RuntimeException("Unsopported symmetric cipher suite");
            }
            var serverInitBuilder = Protocol.ServerInit.newBuilder();
            serverInitBuilder = primeCipherSuite.initServerParams(serverInitBuilder);
            serverInitBuilder.setSymmetricCipherSuite(symmetricCipherSuite.cipherSuiteDescriptor());
            var message = serverInitBuilder.build();
            var masterKey = primeCipherSuite.deriveServerMasterKey(initMessage);
            connection.encoder = symmetricCipherSuite.fromPreMaster(masterKey);
            byte[] initMessageBytes = ProtocolHeader.makeMessage((byte) 1, ProtocolHeader.SERVER_INIT, message.toByteArray());
            connection.connection.send(initMessageBytes);
            return connection;
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    @Override
    public void send(byte[] data) {
        var messageBuilder = Protocol.DataTransfer.newBuilder();
        var encryptedData = this.encoder.encode(data);
        messageBuilder.setData(ByteString.copyFrom(encryptedData));
        // Do not set validation values
        var message = messageBuilder.build();
        this.connection.send(ProtocolHeader.makeMessage((byte) 1, ProtocolHeader.DATA_TRANSFER, message.toByteArray()));
    }

    @Override
    public byte[] receive() {
        try {
            var message = new ProtocolHeader(this.connection.receive());
            if (message.messageCode() != ProtocolHeader.DATA_TRANSFER) {
                throw new RuntimeException("Invalid message code , expected DATA_TRANSFER got " + message.messageCode());
            }
            var body = Protocol.DataTransfer.parseFrom(message.body());
            return this.encoder.decode(body.getData().toByteArray());
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }
}
