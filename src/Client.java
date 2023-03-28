import java.io.*;
import java.net.Socket;

public class Client {
    public static void main(String[] args) throws IOException {
        String host = "localhost";
        int port = 5000;
        Socket socket = new Socket(host, port);
        System.out.println("Connected to server on " + host + ":" + port);

        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

        out.println("hello world");
        System.out.println("Sent message to server: hello world");

        String response = in.readLine();
        System.out.println("Received response from server: " + response);

        in.close();
        out.close();
        socket.close();
    }
}
