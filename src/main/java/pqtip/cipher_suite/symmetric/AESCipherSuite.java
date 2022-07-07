package pqtip.cipher_suite.symmetric;

import pqtip.definitions.Protocol;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class AESCipherSuite implements SymmetricCipherSuite{
    private static class AESEncoder implements Encoder{
        private final Cipher encryptor;
        private final Cipher decryptor;
        private AESEncoder(byte[] seed) {
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec spec = new PBEKeySpec(new char[]{'P','Q','T','I','P'}, seed, 65536, 256);
                var iv = new byte[16];
                SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
                        .getEncoded(), "AES");
                new SecureRandom().nextBytes(iv);
                var vec = new IvParameterSpec(iv);

                this.encryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
                encryptor.init(Cipher.ENCRYPT_MODE, secret, vec);

                this.decryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
                decryptor.init(Cipher.DECRYPT_MODE, secret, vec);
            } catch(Exception e){
                throw new RuntimeException(e);
            }
        }

        @Override
        public byte[] encode(byte[] data) {
            try {
                var padded = new byte[16 + data.length];
                for(int i = 0; i < data.length; i++){
                    padded[i + 16] = data[i];
                }
                var encoded = this.encryptor.doFinal(padded);
                return encoded;
            } catch(Exception e){
                throw new RuntimeException(e);
            }
        }

        @Override
        public byte[] decode(byte[] cipherText) {
            try {
                var decoded = this.decryptor.doFinal(cipherText);
                return Arrays.copyOfRange(decoded, 16, decoded.length);
            } catch(Exception e){
                throw new RuntimeException(e);
            }
        }
    }
    @Override
    public Protocol.SymmetricCipherSuite cipherSuiteDescriptor() {
        return Protocol.SymmetricCipherSuite.AES;
    }

    @Override
    public Encoder fromPreMaster(byte[] preMasterKey) {
        return new AESEncoder(preMasterKey);
    }
}
