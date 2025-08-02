package com.example.demo.Controller;


import com.example.demo.Model.User;
import com.example.demo.Repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Optional;

@Controller
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthController(UserRepository userRepository , PasswordEncoder passwordEncoder) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // Show the custom login page
    @GetMapping("/login")
    public String showLoginPage() {

        return "login"; // returns login.html
    }


    // Show the signup page
    @GetMapping("/signup")
    public String showSignupPage() {

        return "signup"; // returns signup.html
    }

    // Handle the signup form submission

    @PostMapping("/signup")
    public String processSignup(@RequestParam String username, @RequestParam String password, RedirectAttributes redirectAttributes) {
        // ✅ Add this check to ensure the username is a Gmail address
        if (!username.toLowerCase().endsWith("@gmail.com")) {
            redirectAttributes.addFlashAttribute("error", "Invalid email format. Please use a Gmail address.");
            return "redirect:/signup";
        }

        // Check if the username already exists
        if (userRepository.findByUsername(username).isPresent()) {
            redirectAttributes.addFlashAttribute("error", "This Gmail address is already registered!");
            return "redirect:/signup";
        }

        // Encode the password before saving
        String encodedPassword = passwordEncoder.encode(password);
        User newUser = new User(username, encodedPassword);
        userRepository.save(newUser);

        redirectAttributes.addFlashAttribute("success", "Registration successful! Please log in.");
        return "redirect:/login";
    }
}