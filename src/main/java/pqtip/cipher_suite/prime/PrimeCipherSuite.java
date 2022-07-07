package pqtip.cipher_suite.prime;

import pqtip.definitions.Protocol;

public interface PrimeCipherSuite{
    Protocol.ClientInit.Builder initClientParams(Protocol.ClientInit.Builder message);
    Protocol.ServerInit.Builder initServerParams(Protocol.ServerInit.Builder message);
    byte[] deriveServerMasterKey(Protocol.ClientInit client);
    byte[] deriveClientMasterKey(Protocol.ServerInit server);
    Protocol.PrimeCipherSuite cipherSuiteDescriptor();
    Protocol.ServerUnsupportedParams.Builder supportedParameters(Protocol.ServerUnsupportedParams.Builder message);
}