package com.example.demo.Model;

import jakarta.persistence.*;

@Entity
@Table(name = "users") // It's good practice to name the table "users"
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    // --- Constructors ---
    public User() {}

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    // --- Getters and Setters ---
    public int getId() {
        return id; }
    public void setId(int id) {
        this.id = id; }
    public String getUsername() {
        return username; }
    public void setUsername(String username) {
        this.username = username; }
    public String getPassword() {
        return password; }
    public void setPassword(String password) {
        this.password = password; }
}