package pqtip.cipher_suite;

import pqtip.cipher_suite.prime.PrimeCipherSuite;
import pqtip.cipher_suite.prime.SidhNewHopeSuite;
import pqtip.cipher_suite.symmetric.AESCipherSuite;
import pqtip.cipher_suite.symmetric.SymmetricCipherSuite;

import java.util.List;

public class PrototypeCipherSuiteProvider implements CipherSuiteProvider {
    @Override
    public List<PrimeCipherSuite> primeSuites() {
        return List.of(new SidhNewHopeSuite());
    }

    @Override
    public List<SymmetricCipherSuite> symmetricSuites() {
        return List.of(new AESCipherSuite());
    }
}
