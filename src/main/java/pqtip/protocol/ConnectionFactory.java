package pqtip.protocol;
import pqtip.cipher_suite.CipherSuiteProvider;
import pqtip.cipher_suite.prime.PrimeCipherSuite;
import pqtip.cipher_suite.symmetric.SymmetricCipherSuite;
import pqtip.connection.BlockingTransportConnection;
import pqtip.connection.PQTIPConnection;

import java.util.ArrayList;

public class ConnectionFactory{
    private final CipherSuiteProvider suiteProvider;
    public ConnectionFactory(CipherSuiteProvider supportedSuites) {
        this.suiteProvider = supportedSuites;
    }

    public PQTIPConnection secureClientConnection(BlockingTransportConnection baseConnection){
        // No slow flow support, just use first provided prime suite
        return PQTIPConnection.initializeClient(suiteProvider.primeSuites().get(0), suiteProvider.symmetricSuites(), baseConnection);
    }

    public PQTIPConnection secureServerConnection(BlockingTransportConnection baseConnection){
        // No slow flow support, just use first provided prime suite
        return PQTIPConnection.initializeServer(suiteProvider.primeSuites(), suiteProvider.symmetricSuites(), baseConnection);
    }
}