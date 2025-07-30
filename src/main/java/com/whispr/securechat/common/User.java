package com.whispr.securechat.common;

import com.google.gson.annotations.SerializedName;

import java.util.Objects;

/**
 * Represents a user in the Whispr secure chat system.
 * <p>
 * This class contains basic user information such as username and online status.
 * It's used for representing users in the user list and for sending/receiving messages.
 * </p>
 */
public class User {
    /**
     * Gets the username of this user.
     *
     * @return The username
     */
    public String getUsername() {
        return username;
    }

    /** The username of the user */
    @SerializedName("username")
    private String username;

    /** Whether the user is currently online */
    @SerializedName("isOnline")
    private boolean isOnline;

    /**
     * Creates a new User with the specified username and online status.
     * @param username The username of the user
     * @param isOnline Whether the user is currently online
     */
    public User(String username, boolean isOnline){
        this.username = username;
        this.isOnline = isOnline;
    }
    /**
     * Returns a string representation of this user.
     * @return The username of this user
     */
    @Override
    public String toString(){
        return this.username;
    }

    /**
     * Determines if this user is equal to another object.
     * Two users are considered equal if they have the same username,
     * regardless of their online status.
     * @param o The object to compare with
     * @return true if the objects are equal, false otherwise
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return Objects.equals(username, user.username);
    }

    /**
     * Returns a hash code value for this user based on the username.
     * @return A hash code value for this user
     */
    @Override
    public int hashCode() {
        return Objects.hash(username);
    }

}
