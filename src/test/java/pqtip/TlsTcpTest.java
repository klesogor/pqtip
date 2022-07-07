/*
    Courtesy of https://gist.github.com/artem-smotrakov/bd14e4bde4d7238f7e5ab12c697a86a3
 */
package pqtip;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;


/*
 * Don't forget to set the following system properties when you run the class:
 *
 *     javax.net.ssl.keyStore
 *     javax.net.ssl.keyStorePassword
 *     javax.net.ssl.trustStore
 *     javax.net.ssl.trustStorePassword
 *
 * More details can be found in JSSE docs.
 *
 * For example:
 *
 *     java -cp classes \
 *         -Djavax.net.ssl.keyStore=../../resources/keystore \
 *         -Djavax.net.ssl.keyStorePassword=passphrase \
 *         -Djavax.net.ssl.trustStore=../../resources/keystore \
 *         -Djavax.net.ssl.trustStorePassword=passphrase \
 *             TlsTcpTest.java
 *
 * For testing purposes, you can download the keystore file from
 *
 *     https://github.com/openjdk/jdk/tree/master/test/jdk/javax/net/ssl/etc
 */
public class TlsTcpTest {

    private static final int delay = 1000; // in millis
    private static final String[] protocols = new String[] {"TLSv1.3"};
    private static final String[] cipher_suites = new String[] {"TLS_AES_128_GCM_SHA256"};
    private static final String message =
            "LTLS_AES_128_GCM_SHA256";

    public static void main(String[] args) throws Exception {
        try (EchoServer server = EchoServer.create()) {
            new Thread(server).start();
            Thread.sleep(delay);
            long total = 0;
            for(int i = 0; i < 10; i++) {
                long start = System.nanoTime();
                try (SSLSocket socket = createSocket("localhost", server.port())) {
                    InputStream is = new BufferedInputStream(socket.getInputStream());
                    OutputStream os = new BufferedOutputStream(socket.getOutputStream());
                    os.write(message.getBytes());
                    os.flush();
                    byte[] data = new byte[2048];
                    int len = is.read(data);
                    if (len <= 0) {
                        throw new IOException("no data received");
                    }
                    System.out.printf("client received %d bytes: %s%n",
                            len, new String(data, 0, len));
                }
                long end = System.nanoTime();
                System.out.println(String.format("Iteration %d executed in %d ns", i, end - start));
                total += end - start;
            }
            System.out.println(String.format("Finished test, average was %d ns/op", total/10));
        }
    }

    public static SSLSocket createSocket(String host, int port) throws IOException {
        SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault()
                .createSocket(host, port);
        socket.setEnabledProtocols(protocols);
        socket.setEnabledCipherSuites(cipher_suites);
        return socket;
    }

    public static class EchoServer implements Runnable, AutoCloseable {

        private static final int FREE_PORT = 0;

        private final SSLServerSocket sslServerSocket;

        private EchoServer(SSLServerSocket sslServerSocket) {
            this.sslServerSocket = sslServerSocket;
        }

        public int port() {
            return sslServerSocket.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            if (sslServerSocket != null && !sslServerSocket.isClosed()) {
                sslServerSocket.close();
            }
        }

        @Override
        public void run() {
            System.out.printf("server started on port %d%n", port());
            while(true) {
                try (SSLSocket socket = (SSLSocket) sslServerSocket.accept()) {
                    System.out.println("accepted");
                    InputStream is = new BufferedInputStream(socket.getInputStream());
                    OutputStream os = new BufferedOutputStream(socket.getOutputStream());
                    byte[] data = new byte[2048];
                    int len = is.read(data);
                    if (len <= 0) {
                        throw new IOException("no data received");
                    }
                    System.out.printf("server received %d bytes: %s%n",
                            len, new String(data, 0, len));
                    os.write(data, 0, len);
                    os.flush();
                } catch (Exception e) {
                    System.out.printf("exception: %s%n", e.getMessage());
                    e.printStackTrace();
                    System.exit(1);
                }
            }
        }

        public static EchoServer create() throws IOException {
            return create(FREE_PORT);
        }

        public static EchoServer create(int port) throws IOException {
            SSLServerSocket socket = (SSLServerSocket)
                    SSLServerSocketFactory.getDefault().createServerSocket(port);
            socket.setEnabledProtocols(protocols);
            socket.setEnabledCipherSuites(cipher_suites);
            return new EchoServer(socket);
        }
    }
}