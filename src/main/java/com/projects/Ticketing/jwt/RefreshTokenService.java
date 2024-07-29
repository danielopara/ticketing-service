package com.projects.Ticketing.jwt;

import com.projects.Ticketing.model.RefreshToken;
import com.projects.Ticketing.repository.RefreshTokenRepository;
import com.projects.Ticketing.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {
        private final RefreshTokenRepository refreshTokenRepository;
        private final UserRepository userRepository;

        public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, UserRepository userRepository) {
            this.refreshTokenRepository = refreshTokenRepository;
            this.userRepository = userRepository;
        }

        public RefreshToken createRefreshToken(String username) {
            // Find user by email
            var user = userRepository.findByEmail(username)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Check if a refresh token already exists for this user
            Optional<RefreshToken> existingToken = refreshTokenRepository.findByUser(user);
            RefreshToken refreshToken;

            if (existingToken.isPresent()) {
                // Update existing token's expiration date
                refreshToken = existingToken.get();
                refreshToken.setExpireDate(new Date(System.currentTimeMillis() + 604800000));// Set new expiration date
            } else {
                // Create a new refresh token
                refreshToken = RefreshToken.builder()
                        .user(user)
                        .token(UUID.randomUUID().toString())
                        .expireDate(new Date(System.currentTimeMillis() + 604800000)) // Set expiration date (1 day from now)
                        .build();
            }

            return refreshTokenRepository.save(refreshToken);
        }


        public RefreshToken verifyExpiration(RefreshToken token) {
            if (token.getExpireDate().before(new Date())) {
                refreshTokenRepository.delete(token);
                throw new RuntimeException(token.getToken() + " Refresh token has expired. Please make a new sign-in request.");
            }
            return token;
        }
    }

