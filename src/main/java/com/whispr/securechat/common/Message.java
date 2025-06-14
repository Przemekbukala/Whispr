package com.whispr.securechat.common;

import java.io.Serializable;
import java.security.KeyPair;

import com.google.gson.annotations.SerializedName;
import com.whispr.securechat.security.AESEncryptionUtil;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import static com.whispr.securechat.security.RSAEncryptionUtil.generateRSAKeyPair;

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
    @SerializedName("getEncryptedIv")
    private byte[] EncryptedIv;

    public Message(MessageType type, String sender, String recipient, String payload, long timestamp) {
        this.type = type;
        this.sender = sender;
        this.recipient = recipient;
        this.payload = payload;
        this.timestamp = timestamp;
    }

    // durgi kosntruktor
    public Message(MessageType type, String sender, String recipient, String payload, byte[] EncryptedIv, long timestamp) {
        this.type = type;
        this.sender = sender;
        this.recipient = recipient;
        this.payload = payload;
        this.EncryptedIv = EncryptedIv;
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

    public String getpayload() {
        return payload;
    }

    public byte[] getEncryptedIv() {
        return EncryptedIv;
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

    public void setEncryptedIv(byte[] encryptedIv) {this.EncryptedIv = encryptedIv;}

    public void setTimestamp(long type) {this.timestamp = timestamp;}

    @Override
    public String toString() {
        if (type == MessageType.PUBLIC_KEY_EXCHANGE) {
            return "Message{" +
                    "type=" + type +
                    ", sender='" + sender + '\'' +
                    ", timestamp=" + timestamp +
                    '}';
        }
        if (EncryptedIv == null) {
            return "Message{" +
                    "type=" + type +
                    ", sender='" + sender + '\'' +
                    ", recipient='" + recipient + '\'' +
                    ", payload=<no encrypted key+IV>," +
                    " timestamp=" + timestamp +
                    '}';
        }
      return  null;
    }

}
