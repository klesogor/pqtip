package pqtip.cipher_suite;

import pqtip.cipher_suite.prime.PrimeCipherSuite;
import pqtip.cipher_suite.symmetric.SymmetricCipherSuite;

import java.util.List;

public interface CipherSuiteProvider {
    List<PrimeCipherSuite> primeSuites();
    List<SymmetricCipherSuite> symmetricSuites();
}
