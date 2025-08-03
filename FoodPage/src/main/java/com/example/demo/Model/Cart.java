package com.example.demo.Model;

import java.util.ArrayList;
import java.util.List;

// This class represents the user's shopping cart.
public class Cart {

    // A list to hold all the items in the cart.
    private List<CartItem> items;
    // Constructor to create a new cart with an empty list of items.
    public Cart() {
        this.items = new ArrayList<>();
    }

    // Getter method to access the list of items.
    // This is the getItems() method that was missing.
    public List<CartItem> getItems() {
        return items;
    }

    // (Optional) Setter for the list of items.
    public void setItems(List<CartItem> items) {
        this.items = items;
    }
}