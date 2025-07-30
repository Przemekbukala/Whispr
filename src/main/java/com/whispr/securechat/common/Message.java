package com.whispr.securechat.common;

import java.io.Serializable;
import com.google.gson.annotations.SerializedName;

/**
 * Represents a message exchanged between clients and the server.
 */
public class Message implements Serializable {
    /** The type of message, determining how it should be processed */
    @SerializedName("type")
    private MessageType type;
    /** The username of the message sender */
    @SerializedName("sender")
    private String sender;
    /** The username of the intended message recipient */
    @SerializedName("recipient")
    private String recipient;
    /** 
     * The message payload, which can contain encrypted content, public keys, or other data
     * depending on the message type 
     */
    @SerializedName("payload")
    private String payload;
    /** The timestamp when the message was created (in milliseconds since epoch) */
    @SerializedName("timestamp")
    private long timestamp;
    /** 
     * The initialization vector used for AES encryption of the payload
     */
    @SerializedName("getEncryptedIv")
    private byte[] EncryptedIv;

    /**
     * Creates a new message without an initialization vector.
     * This constructor is typically used for messages that don't contain encrypted content.
     * @param type      The message type from {@link MessageType}
     * @param sender    The username of the sender
     * @param recipient The username of the recipient
     * @param payload   The message payload
     * @param timestamp The message creation timestamp
     */
    public Message(MessageType type, String sender, String recipient, String payload, long timestamp) {
        this.type = type;
        this.sender = sender;
        this.recipient = recipient;
        this.payload = payload;
        this.timestamp = timestamp;
    }

    /**
     * Creates a new message with an initialization vector for encrypted content.
     * This constructor is used for messages containing AES-encrypted payloads.
     * @param type       The message type from {@link MessageType}
     * @param sender     The username of the sender
     * @param recipient  The username of the recipient
     * @param payload    The encrypted message payload
     * @param EncryptedIv The initialization vector used for encryption
     * @param timestamp  The message creation timestamp
     */
    public Message(MessageType type, String sender, String recipient, String payload, byte[] EncryptedIv, long timestamp) {
        this.type = type;
        this.sender = sender;
        this.recipient = recipient;
        this.payload = payload;
        this.EncryptedIv = EncryptedIv;
        this.timestamp = timestamp;
    }

    /**
     * Gets the type of this message.
     * @return The message type
     */
    public MessageType getType() {
        return type;
    }

    /**
     * Gets the username of this message.
     * @return The sender's username
     */
    public String getSender() {
        return sender;
    }

    /**
     * Gets the username of the intended recipient.
     * @return The recipient's username
     */
    public String getRecipient() {
        return recipient;
    }

    /**
     * Gets the initialization vector used for AES encryption.
     * @return The initialization vector as a byte array, or null if not present
     */
    public byte[] getEncryptedIv() {
        return EncryptedIv;
    }

    /**
     * Gets the message payload.
     * Depending on the message type, this could be encrypted content, a public key,
     * or other data relevant to the communication protocol.*
     * @return The message payload
     */
    public String getPayload() {
        return payload;
    }

    /**
     * Gets the timestamp when the message was created.
     * @return The creation timestamp in milliseconds since epoch
     */
    public long getTimestamp() {
        return timestamp;
    }

    /**
     * Sets the message payload.
     * @param payload The new payload to set
     */
    public void setPayload(String payload) {
        this.payload = payload;
    }

    /**
     * Sets the initialization vector used for AES encryption.
     *
     * @param encryptedIv The initialization vector as a byte array
     */
    public void setEncryptedIv(byte[] encryptedIv) {
        this.EncryptedIv = encryptedIv;
    }

    /**
     * Sets the message timestamp.
     *
     * @param timestamp The new timestamp in milliseconds since epoch
     */
    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    /**
     * Returns a string representation of this message.
     * For security reasons, sensitive payloads (like encryption keys or long content)
     * are hidden in the string representation.
     * @return A string representation of this message
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Message{");
        sb.append("type=").append(type);
        sb.append(", sender='").append(sender).append('\'');
        sb.append(", recipient='").append(recipient).append('\'');

        if (payload != null && (type == MessageType.PUBLIC_KEY_EXCHANGE || type == MessageType.AES_KEY_EXCHANGE || payload.length() > 70)) {
            sb.append(", payload=<hidden_long_payload>");
        } else {
            sb.append(", payload='").append(payload).append('\'');
        }

        sb.append(", hasIV=").append(EncryptedIv != null);
        sb.append(", timestamp=").append(timestamp);
        sb.append('}');
        return sb.toString();
    }

}
