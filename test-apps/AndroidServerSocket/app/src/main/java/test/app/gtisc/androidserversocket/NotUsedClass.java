package test.app.gtisc.androidserversocket;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Created by ruian on 4/12/16.
 */
public class NotUsedClass {
    ServerSocket serverSocket;

    public NotUsedClass() {
        int SocketServerPORT = 8888;
        try {
            serverSocket = new ServerSocket(SocketServerPORT);

            while (true) {
                Socket socket = serverSocket.accept();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
