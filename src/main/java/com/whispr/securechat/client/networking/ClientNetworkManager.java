package com.whispr.securechat.client.networking;

import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.io.BufferedReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;

import com.whispr.securechat.common.Message;

import static com.whispr.securechat.common.MessageType.CHAT_MESSAGE;
/**
 * Manages network communication for the client side of the secure chat application.
 * This class handles sending and receiving messages to/from the server, and runs
 * in its own thread to continuously listen for incoming messages.
 */
public class ClientNetworkManager implements Runnable {
    /** The socket connection to the server */
        public Socket socket;
    /** BufferedReader for reading from standard input (used for testing) */
    public BufferedReader stdin;
    /** Output stream for sending serialized objects to the server */
    private ObjectOutputStream objectOut;
    /** Input stream for receiving serialized objects from the server */
    private ObjectInputStream objectIn;
    /** Callback interface for handling received messages */
    private MessageReceiver messageReceiver;
    /** Callback interface for handling connection status changes */
    private ConnectionStatusNotifier statusNotifier;


    /**
     * Constructs a new ClientNetworkManager with the specified socket connection.
     * Initializes the input/output streams and standard input reader.
     * @param socket The socket connection to the server.
     * @throws RuntimeException if stream initialization fails.
     */

        public ClientNetworkManager(Socket socket) {
            this.socket = socket;
            try {
                this.objectOut = new ObjectOutputStream(socket.getOutputStream());
                this.objectOut.flush();  //opróznia bufor i wysyła wiadomość
                this.objectIn = new ObjectInputStream(socket.getInputStream());
                this.stdin = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    /**
     * Sets the message receiver callback for handling incoming messages.
     * @param receiver The MessageReceiver implementation to handle received messages
     */

    public void setMessageReceiver(MessageReceiver receiver) {
            this.messageReceiver = receiver;
        }
    /**
     * Sends a message object to the server.
     * (This method is synchronized to prevent concurrent access to the output stream.)
     * @param message The Message object to send to the server
     * @throws Exception If an error occurs during message transmission
     */

        public synchronized void  sendData(Message message) throws Exception {
                        objectOut.writeObject(message);
                        objectOut.flush();
                        System.out.println("Klient: " + message);
        }
    /**
     * Main execution loop for the network manager thread.
     * Continuously listens for incoming messages from the server and processes them.
     * <p>The method handles different types of messages and delegates processing
     * to the registered MessageReceiver. In case of connection issues, it notifies
     * the ConnectionStatusNotifier and closes all resources.</p>
     */

    @Override
        public void run() {
            try {
                while (!socket.isClosed()) {
                    Object obj = objectIn.readObject();
                    if (obj instanceof Message message) {
                        if(message.getType()==CHAT_MESSAGE){
                            System.out.println(message);
                        }else {
                            System.out.println("Message was received from " + message.getSender() + ": "+" message type: "+message.getType());
                        }
                        if (messageReceiver != null) {
                            messageReceiver.onMessageReceived(message);
                        } else {
                            System.err.println("No message recipient set (messageReceiver == null)");
                        }
                    } else {
                        System.err.println("A non-Message object was received: " + obj.getClass());
                    }
                }
            } catch (IOException e) {
                System.err.println("The connection to the server was interrupted.");
                if (statusNotifier != null) {
                    statusNotifier.onConnectionLost();
                }

            } catch (ClassNotFoundException e) {
                System.err.println("Unknown class of object received from server.");
            } finally {
                close();
            }
        }
    /**
     * Closes all network resources including streams and socket connection.
     */
        public void close() {
            try {
                if (objectIn != null) objectIn.close();
                if (objectOut != null) objectOut.close();
                if (stdin != null) stdin.close();
                if (socket != null) socket.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    /**
     * Sets the connection status notifier for handling connection state changes.
     * @param notifier The ConnectionStatusNotifier implementation to handle connection events
     */
    public void setConnectionStatusNotifier(ConnectionStatusNotifier notifier) {
        this.statusNotifier = notifier;
        }
    /**
     * Interface for receiving and processing incoming messages from the server.
     * Implementations of this interface define how different types of messages
     * should be handled by the client application.
     */
        public interface MessageReceiver {
        /**
         * Called when a message is received from the server.
         * @param message The received Message object
         */

        void onMessageReceived(Message message);
        }
    /**
     * Interface for receiving notifications about connection status changes.
     * This allows the client application to respond appropriately connection loss.
     */
        public interface ConnectionStatusNotifier {
            void onConnectionLost();
        }


}