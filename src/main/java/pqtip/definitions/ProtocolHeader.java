package pqtip.definitions;

import java.nio.ByteBuffer;
import java.util.Arrays;

public final class ProtocolHeader {
    public static final byte CLIENT_INIT = 1;
    public static final byte SERVER_INIT = 2;
    public static final byte UNSUPPORTED_SERVER_PARAMS = 3;
    public static final byte DATA_TRANSFER = 4;
    private final byte[] message;

    public ProtocolHeader(byte[] message) {
        this.message = message;
    }

    public static byte[] makeMessage(byte version, byte type, byte[] body){
        try {
            var message = ByteBuffer.allocate(body.length + 10);
            message.put(version);
            message.put(type);
            message.putInt(body.length + 10);
            message.put(getHash(body));
            message.put(body);
            return message.array();
        } catch (Exception ex){
            throw new RuntimeException((ex));
        }
    }

    private static byte[] getHash(byte[] body){
        // No body integrity for version 0.1
        return new byte[]{127,63,31,15};
    }

    public boolean isValid(){
        // mac offset is 1 + 1 + 4 = 6 bytes
        return this.message[6] == 127 && this.message[7] == 63 && this.message[8] == 31 && this.message[9] == 15;
    }
    public int messageCode(){
        return this.message[1];
    }
    public byte[] body(){
        return Arrays.copyOfRange(this.message, 10, this.message.length);
    }
}
