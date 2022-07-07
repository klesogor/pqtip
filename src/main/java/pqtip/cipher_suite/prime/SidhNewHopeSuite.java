package pqtip.cipher_suite.prime;

import com.google.protobuf.ByteString;
import pqtip.cipher_suite.prime.sidh.SidhKeyExchange;
import pqtip.cipher_suite.prime.sidh.SidhKeyPair;
import pqtip.cipher_suite.prime.sidh.SidhPublicKey;
import pqtip.definitions.Protocol;

public class SidhNewHopeSuite implements PrimeCipherSuite {
    private SidhKeyPair key;
    SidhKeyExchange kex;
    @Override
    public Protocol.ClientInit.Builder initClientParams(Protocol.ClientInit.Builder message) {
        kex = new SidhKeyExchange("sidhP503");
        key = kex.generateKeyPair(SidhKeyExchange.ALICE);
        var paramsBuilder = Protocol.SidhKeyExchangeParams.newBuilder();
        paramsBuilder.setPublicKey(ByteString.copyFrom(key.getPublicKey().serialize()));
        return message.setSidhKeParams(paramsBuilder.build());
    }

    @Override
    public Protocol.ServerInit.Builder initServerParams(Protocol.ServerInit.Builder message) {
        kex = new SidhKeyExchange("sidhP503");
        key = kex.generateKeyPair(SidhKeyExchange.BOB);
        var paramsBuilder = Protocol.SidhKeyExchangeParams.newBuilder();
        paramsBuilder.setPublicKey(ByteString.copyFrom(key.getPublicKey().serialize()));
        return message.setSidhKeParams(paramsBuilder.build());
    }

    @Override
    public byte[] deriveServerMasterKey(Protocol.ClientInit client) {
        var pkBytes = client.getSidhKeParams().getPublicKey().toByteArray();
        var pk = new SidhPublicKey(pkBytes);
        return kex.calculateAgreementB(this.key.getPrivateKey(), pk);
    }

    @Override
    public byte[] deriveClientMasterKey(Protocol.ServerInit server) {
        var pkBytes = server.getSidhKeParams().getPublicKey().toByteArray();
        var pk = new SidhPublicKey(pkBytes);
        return kex.calculateAgreementA(this.key.getPrivateKey(), pk);
    }

    @Override
    public Protocol.PrimeCipherSuite cipherSuiteDescriptor() {
        return Protocol.PrimeCipherSuite.SIDH_NEW_HOPE;
    }

    @Override
    public Protocol.ServerUnsupportedParams.Builder supportedParameters(Protocol.ServerUnsupportedParams.Builder message) {
        throw new RuntimeException("Not implemented");
    }
}
