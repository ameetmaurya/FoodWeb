package com.example.demo.Controller;

import com.example.demo.CustomItemRequest;
import com.example.demo.Model.CartItem;
import com.example.demo.Model.Product;
import com.example.demo.Repository.repo;
import com.example.demo.services.cart_service;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@Controller
public class controller {

    private final repo repository;
    private final cart_service cartService;

    public controller(repo repository, cart_service cartService) {
        this.repository = repository;
        this.cartService = cartService;
    }

    @PostConstruct
    public void initializeDatabase() {
        if (repository.count() == 0) {
            List<Product> initialProducts = Arrays.asList(
                    new Product(0, "Mixed Vegetable Salad", 249, "images/CaesarSalad.png", "Fresh mixed vegetables with olive oil dressing"),
                    new Product(0, "Mixed Fruit Salad", 299, "images/fruitsalad.png", "Seasonal fruits with honey-lime dressing"),
                    new Product(0, "Garden Fresh Salad", 279, "images/greensalad.png", "Mixed greens with nuts and seeds"),
                    new Product(0, "Orange Sunrise", 149, "images/orangejuice.png", "Fresh orange juice with pulp"),
                    new Product(0, "Watermelon Refresh", 199, "images/watermelon.png", "Pure watermelon juice with mint"),
                    new Product(0, "Berry Juice", 179, "images/berry.png", "Sweet berry juice with a hint of stawberry")
            );
            repository.saveAll(initialProducts);
        }
    }

    @GetMapping("/")
    public String showLandingPage() {

        return "Main_Home_page"; // This should match your landing.html
    }

    @GetMapping("/home")
    public String home() {

        return "home_page";
    }

    @GetMapping("/customize")
    public String customize(Model model) {
        int cartSize = cartService.getCartItems().size();

        // ✅ Add the cart size to the model so the HTML can access it
        model.addAttribute("cartSize", cartSize);
        return "Customize";
    }

    @GetMapping("/subscribe")
    public String subscribe() {

        return "Subscribe";
    }
    @GetMapping("/menu")
    public String showMenu(Model model) {
        List<Product> productsFromDb = repository.findAll();
        List<CartItem> cartItems = cartService.getCartItems();

        List<Integer> cartItemIds = new ArrayList<>();
        Map<Integer, Integer> cartQuantities = new HashMap<>();
        for (CartItem item : cartItems) {
            cartItemIds.add(item.getId());
            cartQuantities.put(item.getId(), item.getQuantity());
        }

        model.addAttribute("products", productsFromDb);
        model.addAttribute("cartSize", cartItems.size());
        model.addAttribute("cartItemIds", cartItemIds);
        model.addAttribute("cartQuantities", cartQuantities);

        return "Menu";
    }


    // ✅ View Cart
    @GetMapping("/cart")
    public String viewCart(Model model) {
        List<CartItem> cartItems = cartService.getCartItems();
        double totalAmount = cartItems.stream().mapToDouble(CartItem::getSubtotal).sum();
        model.addAttribute("cartItems", cartItems);
        model.addAttribute("totalAmount", totalAmount);
        return "Cart";
    }

    // ✅ Add Product to Cart (AJAX)
    @PostMapping("/add-to-cart/{id}")
    @ResponseBody
    public Map<String, Object> addToCart(@PathVariable int id) {
        Optional<Product> productOpt = repository.findById(id);
        productOpt.ifPresent(cartService::addProduct);

        Map<String, Object> response = new HashMap<>();
        response.put("cartSize", cartService.getCartItems().size());
        response.put("quantity", cartService.getQuantity(id));
        return response;
    }

    // ✅ Remove Product (AJAX)
    @GetMapping("/cart/remove/{id}")
    @ResponseBody
    public Map<String, Object> removeProduct(@PathVariable int id) {
        cartService.removeProduct(id);

        Map<String, Object> response = new HashMap<>();
        response.put("cartSize", cartService.getCartItems().size());
        response.put("totalAmount", cartService.getCartItems().stream().mapToDouble(CartItem::getSubtotal).sum());
        return response;
    }

    // ✅ Update Cart Quantity (AJAX)
    @PostMapping("/cart/update/{id}")
    @ResponseBody
    public Map<String, Object> updateCartQuantity(@PathVariable int id, @RequestParam int quantity) {
        cartService.updateQuantity(id, quantity);

        Map<String, Object> response = new HashMap<>();
        response.put("cartSize", cartService.getCartItems().size());
        response.put("quantity", quantity);
        response.put("totalAmount", cartService.getCartItems().stream().mapToDouble(CartItem::getSubtotal).sum());
        return response;
    }


    // In your controller.java

    @PostMapping("/cart/add/custom")
    @ResponseBody
    public ResponseEntity<?> addCustomItemToCart(@RequestBody CustomItemRequest customItem) { // ✅ REMOVED HttpSession

        // Call the service method directly, without the session
        cartService.addCustomItemToCart(customItem.getName(), customItem.getPrice());

        // Get the cart size directly from the service
        int cartSize = cartService.getCartItems().size();
        return ResponseEntity.ok(Map.of("cartSize", cartSize));
    }

}
