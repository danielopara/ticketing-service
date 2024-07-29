package com.projects.Ticketing.controller;

import com.projects.Ticketing.dtos.RefreshTokenDTO;
import com.projects.Ticketing.dtos.UserLoginDto;
import com.projects.Ticketing.jwt.JwtService;
import com.projects.Ticketing.jwt.RefreshTokenService;
import com.projects.Ticketing.model.RefreshToken;
import com.projects.Ticketing.model.User;
import com.projects.Ticketing.repository.RefreshTokenRepository;
import com.projects.Ticketing.repository.UserRepository;
import com.projects.Ticketing.response.BaseResponse;
import com.projects.Ticketing.service.user.implementation.UserServiceImplementation;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    Logger logger = LoggerFactory.getLogger(UserController.class.getName());

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenRepository repo;
    private final UserServiceImplementation userService;

    public AuthController(JwtService jwtService, UserRepository userRepository, RefreshTokenService refreshTokenService, RefreshTokenRepository repo, UserServiceImplementation userService) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.refreshTokenService = refreshTokenService;
        this.repo = repo;
        this.userService = userService;
    }

//    @PostMapping("/findToken")
//    public String findToken(@RequestBody RefreshTokenDTO refreshTokenDTO) {
//        Optional<RefreshToken> optionalToken = repo.findByToken(refreshTokenDTO.getToken());
//
//        if (optionalToken.isEmpty()) {
//            throw new RuntimeException("Refresh token is not in database!");
//        }
//
//        RefreshToken refreshToken = optionalToken.get();
//
//        RefreshToken validRefreshToken = refreshTokenService.verifyExpiration(refreshToken);
//
//        User user = validRefreshToken.getUser();
//
//        Authentication authentication = new UsernamePasswordAuthenticationToken(
//                user,
//                null,
//                user.getAuthorities()
//        );
//
//        String accessToken = jwtService.generateToken(authentication);
//
//        return "token: " + accessToken;
//    }



    @PostMapping("/refreshToken")
    public ResponseEntity<?> generateRefreshToken(@RequestBody RefreshTokenDTO refreshTokenDTO) {
        System.out.println("Received token request: " + refreshTokenDTO.getToken());

        Optional<RefreshToken> existingTokenOpt = repo.findByToken(refreshTokenDTO.getToken());

        if (existingTokenOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token does not exist.");
        }

        // Verify if the refresh token has expired
        RefreshToken validRefreshToken = refreshTokenService.verifyExpiration(existingTokenOpt.get());

        // Extract username from the valid refresh token
        User user1 = validRefreshToken.getUser();
        String email = user1.getEmail();

        // Find the user by email (username)
        Optional<User> userOpt = userRepository.findByEmail(email);

        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("User does not exist.");
        }

        User user = userOpt.get();

        // Create an Authentication object from the User entity
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                user,
                null,
                user.getAuthorities()
        );

        // Generate a new access token using the user's details
        String newAccessToken = jwtService.generateToken(authentication);

        // Optionally, generate a new refresh token
        RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(email);
        String newRefreshTokenValue = newRefreshToken.getToken();

        // Return new tokens to the client
        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", newAccessToken);
        tokens.put("refreshToken", newRefreshTokenValue);

        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody UserLoginDto dto){
        BaseResponse response = userService.login(dto);
        logger.info(String.valueOf(dto));
        if(response.getStatusCode() == HttpServletResponse.SC_OK){
            return new ResponseEntity<>(response, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
    }


}
