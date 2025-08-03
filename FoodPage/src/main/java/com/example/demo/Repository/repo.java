package com.example.demo.Repository;

import com.example.demo.Model.Product;
import org.springframework.data.jpa.repository.JpaRepository;

public interface repo extends JpaRepository<Product, Integer> {
}
