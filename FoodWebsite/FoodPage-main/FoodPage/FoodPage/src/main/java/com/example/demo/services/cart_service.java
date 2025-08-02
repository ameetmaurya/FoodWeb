package com.example.demo.services;

import com.example.demo.Model.Cart;
import com.example.demo.Model.CartItem;
import com.example.demo.Model.Product;
import jakarta.servlet.http.HttpSession;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Service;
import org.springframework.web.context.WebApplicationContext;

import java.util.ArrayList;
import java.util.List;

@Service
@Scope(value = WebApplicationContext.SCOPE_SESSION, proxyMode = ScopedProxyMode.TARGET_CLASS)
public class cart_service {



    private final List<CartItem> cartItems = new ArrayList<>();

    public List<CartItem> getCartItems() {

        return cartItems;
    }

    public void addProduct(Product product) {
        for (CartItem item : cartItems) {
            if (item.getId() == product.getId()) {
                item.setQuantity(item.getQuantity() + 1);
                return;
            }
        }
        cartItems.add(new CartItem(product.getId(), product.getName(), product.getPrice(), 1));
    }

    public void removeProduct(int id) {
        cartItems.removeIf(item -> item.getId() == id);
    }

    public void updateQuantity(int id, int quantity) {
        for (CartItem item : cartItems) {
            if (item.getId() == id) {
                item.setQuantity(quantity);
                return;
            }
        }
    }

    public int getQuantity(int id) {
        return cartItems.stream()
                .filter(item -> item.getId() == id)
                .map(CartItem::getQuantity)
                .findFirst()
                .orElse(0);
    }



    public void addCustomItemToCart(String name, double price) {

        // Create a new cart item for the custom product
        CartItem newItem = new CartItem();
        newItem.setName(name);
        newItem.setPrice(price);
        newItem.setQuantity(1);
        cartItems.add(newItem);
    }

}
