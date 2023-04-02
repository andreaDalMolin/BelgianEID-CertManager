import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
    public static void main(String[] args) throws IOException, InterruptedException {
        int port = 5000;
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Server started on port " + port);

        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("Client connected from " + clientSocket.getInetAddress());

            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                System.out.println("Received message from client: " + inputLine);
                if (inputLine.equals("hello world")) {
                    out.println("hello to you");
                    break;
                } else if (inputLine.equals("123")) {
                    System.out.println("Fetching user data...");
                    Thread.sleep(3000);
                    out.println("Chiffrer(challenge)");
                } else {
                    System.out.println("MESSAGE WAS : " + inputLine);
                }
            }

            in.close();
            out.close();
            clientSocket.close();
        }
    }
}
