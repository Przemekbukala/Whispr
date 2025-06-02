package com.whispr.securechat.common;

import java.io.Serializable;
import com.google.gson.annotations.SerializedName;

public class Message implements Serializable {
    @SerializedName("type")
    private MessageType type;
    @SerializedName("sender")
    private String sender;
    @SerializedName("recipient")
    private String recipient;
    @SerializedName("payload") // Zawiera zaszyfrowaną treść lub klucz publiczny itp.
    private String payload;
    @SerializedName("timestamp")
    private long timestamp;

    public Message(MessageType type, String sender, String recipient, String payload, long timestamp) {
        this.type = type;
        this.sender = sender;
        this.recipient = recipient;
        this.payload = payload;
        this.timestamp = timestamp;
    }

    public MessageType getType() {
        return type;
    }

    public String getSender() {
        return sender;
    }

    public String getRecipient() {
        return recipient;
    }

    public String getPayload() {
        return payload;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    @Override
    public String toString() {
        return "Message{" +
                "type=" + type +
                ", sender='" + sender + '\'' +
                ", recipient='" + recipient + '\'' +
                ", payload='" + payload + '\'' +
                ", timestamp=" + timestamp +
                '}';
    }
}
