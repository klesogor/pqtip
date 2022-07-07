package pqtip.cipher_suite.symmetric;

import pqtip.definitions.Protocol;

public interface SymmetricCipherSuite{
    Protocol.SymmetricCipherSuite cipherSuiteDescriptor();
    Encoder fromPreMaster(byte[] preMasterKey);
}