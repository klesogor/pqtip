package pqtip.connection;

import java.io.*;
import java.net.Socket;
import java.util.Arrays;

public class BlockingSocketAdapter implements BlockingTransportConnection{
    private final Socket socket;
    private final InputStream socketIn;
    private final OutputStream socketOut;
    // 1 mb buffer
    private final byte[] buffer = new byte[1048576];

    public BlockingSocketAdapter(Socket socket) throws IOException {
        this.socket = socket;
        this.socketIn = socket.getInputStream();
        this.socketOut = socket.getOutputStream();
    }

    @Override
    public void send(byte[] data) {
        try {
            socketOut.write(data);
            socketOut.flush();
        } catch (Exception ex){
            throw new RuntimeException(ex);
        }
    }

    @Override
    public byte[] receive() {
        try {
            var read = socketIn.read(buffer);
            return Arrays.copyOfRange(buffer,0, read);
        } catch (Exception ex){
            throw new RuntimeException(ex);
        }
    }
}
