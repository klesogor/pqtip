package pqtip.cipher_suite.symmetric;

public interface Encoder{
    byte[] encode(byte[] data);
    byte[] decode(byte[] cipherText);
}