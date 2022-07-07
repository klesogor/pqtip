package pqtip.connection;

public interface BlockingTransportConnection{
    void send(byte[] data);
    byte[] receive();
}