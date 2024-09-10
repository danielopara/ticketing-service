package com.projects.Ticketing.service.auth;

import com.projects.Ticketing.dtos.RefreshTokenDto;
import com.projects.Ticketing.dtos.UserLoginDto;
import com.projects.Ticketing.jwt.JwtService;
import com.projects.Ticketing.model.User;
import com.projects.Ticketing.repository.UserRepository;
import com.projects.Ticketing.response.BaseResponse;
import com.projects.Ticketing.service.user.implementation.UserServiceImplementation;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Service
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepository;

    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    //logger
    Logger logger = LoggerFactory.getLogger(UserServiceImplementation.class.getName());

    public AuthServiceImpl(JwtService jwtService, AuthenticationManager authenticationManager,
                           UserRepository userRepository) {
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
    }


    @Override
    public BaseResponse loginService(UserLoginDto dto) {
        try {

            if (dto == null) {
                return new BaseResponse(
                        HttpStatus.BAD_REQUEST.value(),
                        "Invalid input data.",
                        null,
                        null);
            }

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            dto.getUsername(),
                            dto.getPassword()));

            // Check if the authentication was successful
            if (authentication == null || !authentication.isAuthenticated()) {
                return new BaseResponse(
                        HttpServletResponse.SC_BAD_REQUEST,
                        "User email or password is incorrect",
                        null,
                        null
                );
            }

            // Generate JWT token
            String token = jwtService.generateAccessToken(authentication);
            String refreshToken = jwtService.generateRefreshToken(authentication);

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("accessToken", token);
            responseData.put("refreshToken", refreshToken);
            jwtService.extractTokenCreation(token);

            return new BaseResponse(
                    HttpServletResponse.SC_OK,
                    "Login successful",
                    responseData,
                    null
            );

        } catch (UsernameNotFoundException | BadCredentialsException e) {
            // Specific handling for failed authentication
            return new BaseResponse(
                    HttpServletResponse.SC_BAD_REQUEST,
                    "User email or password is incorrect",
                    null,
                    e.getMessage()
            );
        } catch (AuthenticationException e) {
            // General handling for any other authentication exceptions
            logger.warn(String.valueOf(e));
            return new BaseResponse(
                    HttpStatus.BAD_REQUEST.value(),
                    "Authentication failed",
                    null,
                    e.getMessage()
            );
        } catch (Exception e) {
            // Handling for unexpected exceptions
            logger.error("Unexpected error occurred", e);
            return new BaseResponse(
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "Internal server error",
                    null,
                    e.getMessage()
            );
        }
    }

    @Override
    public BaseResponse refreshToken(RefreshTokenDto refreshTokenDto) {
        try{
            String refreshToken = refreshTokenDto.getRefreshToken();
            String username = jwtService.extractUsername(refreshToken);

            Optional<User> userEmail = userRepository.findByEmail(username);

            if(userEmail.isEmpty()){
                return new BaseResponse(
                        HttpServletResponse.SC_NOT_FOUND,
                        "email not found",
                        null,
                        null
                );
            }
            boolean tokenValid = jwtService.isTokenValid(refreshToken, userEmail.get());

            if(!tokenValid){
                return new BaseResponse(
                        HttpServletResponse.SC_FORBIDDEN,
                        "token is invalid",
                        null,
                        null
                );
            }

            String token = jwtService.generateAccessTokenWithRefreshToken(refreshToken);
            return new BaseResponse(
                    HttpServletResponse.SC_OK,
                    "access token generated",
                    token,
                    null
            );


        } catch (Exception e){
            logger.error("Unexpected error occurred", e);
            return new BaseResponse(
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "Internal server error",
                    null,
                    e.getMessage()
            );
        }
    }

}