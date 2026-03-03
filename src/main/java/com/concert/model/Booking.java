package com.concert.model;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

/**
 * Booking entity model.
 *
 * VULNERABILITIES DEMONSTRATED:
 * 1. Implements Serializable without readObject validation (unsafe deserialization)
 * 2. Sensitive payment data stored in plain text
 */
@Entity
@Table(name = "bookings")
public class Booking implements Serializable {

    // VULNERABILITY: No serialVersionUID control
    @SuppressWarnings("unused")
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    private String concertName;
    private String concertVenue;
    private String seatNumber;
    private int quantity;
    private double totalPrice;

    // VULNERABILITY: Raw payment details stored in the booking record
    private String paymentCardNumber;
    private String paymentCardCvv;
    private String paymentCardHolder;

    private String status; // PENDING, CONFIRMED, CANCELLED

    @Temporal(TemporalType.TIMESTAMP)
    private Date bookingDate;

    // VULNERABILITY: Internal transaction reference exposed directly
    private String internalTransactionRef;

    public Booking() {}

    public Booking(User user, String concertName, String seatNumber, int quantity, double totalPrice) {
        this.user = user;
        this.concertName = concertName;
        this.seatNumber = seatNumber;
        this.quantity = quantity;
        this.totalPrice = totalPrice;
        this.status = "PENDING";
        this.bookingDate = new Date();
        // VULNERABILITY: Predictable transaction reference
        this.internalTransactionRef = "TXN-" + user.getUsername() + "-" + System.currentTimeMillis();
    }

    // --- Getters and Setters ---

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }

    public String getConcertName() { return concertName; }
    public void setConcertName(String concertName) { this.concertName = concertName; }

    public String getConcertVenue() { return concertVenue; }
    public void setConcertVenue(String concertVenue) { this.concertVenue = concertVenue; }

    public String getSeatNumber() { return seatNumber; }
    public void setSeatNumber(String seatNumber) { this.seatNumber = seatNumber; }

    public int getQuantity() { return quantity; }
    public void setQuantity(int quantity) { this.quantity = quantity; }

    public double getTotalPrice() { return totalPrice; }
    public void setTotalPrice(double totalPrice) { this.totalPrice = totalPrice; }

    public String getPaymentCardNumber() { return paymentCardNumber; }
    public void setPaymentCardNumber(String paymentCardNumber) { this.paymentCardNumber = paymentCardNumber; }

    public String getPaymentCardCvv() { return paymentCardCvv; }
    public void setPaymentCardCvv(String paymentCardCvv) { this.paymentCardCvv = paymentCardCvv; }

    public String getPaymentCardHolder() { return paymentCardHolder; }
    public void setPaymentCardHolder(String paymentCardHolder) { this.paymentCardHolder = paymentCardHolder; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public Date getBookingDate() { return bookingDate; }
    public void setBookingDate(Date bookingDate) { this.bookingDate = bookingDate; }

    public String getInternalTransactionRef() { return internalTransactionRef; }
    public void setInternalTransactionRef(String internalTransactionRef) {
        this.internalTransactionRef = internalTransactionRef;
    }
}

// Made with Bob
