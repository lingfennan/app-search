package test.app.gtisc.androidserversocket;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.util.Log;
import android.widget.Toast;

public class SocketService extends Service implements Runnable {
    public static final String SERVERIP = "localhost"; //your computer IP address should be written here
    public static final int SERVERPORT = 5000;
    private final IBinder myBinder = new LocalBinder();
    PrintWriter out;
    ServerSocket serverSocket;
    InetAddress serverAddr;

    @Override
    public IBinder onBind(Intent intent) {
        // TODO Auto-generated method stub
        System.out.println("I am in Ibinder onBind method");
        return myBinder;
    }

    public class LocalBinder extends Binder {
        public SocketService getService() {
            System.out.println("I am in Localbinder ");
            return SocketService.this;
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        System.out.println("I am in on create");

        // Test type casting
        new Thread( (Runnable) new connectSocket() ).start();

        // Test identity statement
        new Thread( (Runnable) this).start();

        // Test security package usage (not matching)
        try {
            getMD5String("I shouldn't exist in impact analysis");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void IsBoundable(){
        Toast.makeText(this,"I bind like butter", Toast.LENGTH_LONG).show();
    }

    public void sendMessage(String message){
        if (out != null && !out.checkError()) {
            System.out.println("in sendMessage"+message);
            out.println(message);
            out.flush();
        }
    }

    public void run() {
        Runnable connect = new connectSocket();
        new Thread(connect).start();

        // Test security package usage (matching)
        try {
            getMD5String("I should exist in impact analysis");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    @Override
    public int onStartCommand(Intent intent,int flags, int startId){
        super.onStartCommand(intent, flags, startId);
        System.out.println("I am in on start");
        //  Toast.makeText(this,"Service created ...", Toast.LENGTH_LONG).show();
        Runnable connect = new connectSocket();
        new Thread(connect).start();
        return START_STICKY;
    }

    class connectSocket implements Runnable {

        static final int SocketServerPORT = 7070;
        int count = 0;

        @Override
        public void run() {
            try {
                serverSocket = new ServerSocket(SocketServerPORT);
                String message = "";
                while (true) {
                    Socket socket = serverSocket.accept();
                    count++;
                    message += "#" + count + " from " + socket.getInetAddress()
                            + ":" + socket.getPort() + "\n";
                }
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }

    public static String getMD5String(String plaintext) throws NoSuchAlgorithmException {
        MessageDigest m = MessageDigest.getInstance("MD5");
        m.reset();
        m.update(plaintext.getBytes());
        byte[] digest = m.digest();
        BigInteger bigInt = new BigInteger(1,digest);
        String hashText = bigInt.toString(16);
        // Now we need to zero pad it if you actually want the full 32 chars.
        while(hashText.length() < 32 ){
            hashText = "0"+hashText;
        }
        return hashText;
    }
}
