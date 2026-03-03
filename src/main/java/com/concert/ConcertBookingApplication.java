package com.concert;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Concert Booking System - Main Application Entry Point
 *
 * WARNING: This application is intentionally built with security vulnerabilities
 * for educational and demonstration purposes only.
 * DO NOT deploy this in a production environment.
 */
@SpringBootApplication
public class ConcertBookingApplication {

    public static void main(String[] args) {
        SpringApplication.run(ConcertBookingApplication.class, args);
        System.out.println("==============================================");
        System.out.println("  Concert Booking System started successfully");
        System.out.println("  Admin panel: http://localhost:8080/admin");
        System.out.println("  Debug panel: http://localhost:8080/debug");
        System.out.println("==============================================");
    }
}

// Made with Bob
