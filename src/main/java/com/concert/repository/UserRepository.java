package com.concert.repository;

import com.concert.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * User JPA Repository.
 *
 * VULNERABILITY: Native query with string interpolation risk if used carelessly.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    // VULNERABILITY: Native query exposes internal table/column structure
    @Query(value = "SELECT * FROM users WHERE username = ?1 AND password = ?2", nativeQuery = true)
    Optional<User> findByUsernameAndPassword(String username, String password);
}

// Made with Bob
