package com.projects.Ticketing.service.auth;

import com.projects.Ticketing.dtos.RefreshTokenDto;
import com.projects.Ticketing.dtos.UserLoginDto;
import com.projects.Ticketing.jwt.JwtService;
import com.projects.Ticketing.model.RefreshToken;
import com.projects.Ticketing.model.User;
import com.projects.Ticketing.repository.RefreshTokenRepository;
import com.projects.Ticketing.repository.UserRepository;
import com.projects.Ticketing.response.BaseResponse;
import com.projects.Ticketing.response.TokenResponse;
import com.projects.Ticketing.service.user.implementation.UserServiceImplementation;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.*;

@Slf4j
@Service
public class AuthServiceImpl implements AuthService {

    @Value("${REFRESH_TOKEN_EXPIRATION_MS}")
    private long refreshTokenMs;

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepo;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    //logger
    Logger logger = LoggerFactory.getLogger(UserServiceImplementation.class.getName());


    public boolean isRefreshTokenExpired(RefreshToken refreshToken) {
        Date now = new Date();
        return refreshToken.getExpireDate().before(now);
    }


    public AuthServiceImpl(JwtService jwtService, AuthenticationManager authenticationManager,
                           UserRepository userRepository, RefreshTokenRepository refreshTokenRepo) {
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.refreshTokenRepo = refreshTokenRepo;
    }

    @Override
    public RefreshToken createRefreshToken(Long id) {
        RefreshToken refreshToken = new RefreshToken();

        Optional<User> userId = userRepository.findById(id);

        if(userId.isEmpty()){
            throw new RuntimeException("user id does not exist");
        }

        refreshToken.setUser(userId.get());
        refreshToken.setExpireDate((new Date(System.currentTimeMillis() + refreshTokenMs)));
        refreshToken.setToken(UUID.randomUUID().toString());

        refreshTokenRepo.save(refreshToken);

        return refreshToken;
    }

    @Override
    public TokenResponse loginService(UserLoginDto dto) {
        try {

            if (dto == null) {
                return new TokenResponse(
                        HttpStatus.NO_CONTENT.value(),
                        "no content",
                        null,
                        null,
                        null
                );
            }

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            dto.getUsername(),
                            dto.getPassword()));

            // Check if the authentication was successful
            if (authentication == null || !authentication.isAuthenticated()) {
                return new TokenResponse(
                        HttpServletResponse.SC_BAD_REQUEST,
                        "User email or password is incorrect",
                        null,
                        null,
                        null
                );
            }

            // Generate JWT token
            String token = jwtService.generateAccessToken(authentication);

            // generate refresh token
            User user = userRepository.findByEmail(dto.getUsername()).
                    orElseThrow(()-> new RuntimeException("ERROR with logging in"));

            RefreshToken refreshToken = createRefreshToken(user.getId());

//            Map<String, Object> responseData = new HashMap<>();
//            responseData.put("accessToken", token);
//            responseData.put("refreshToken", refreshToken.getToken());
//            jwtService.extractTokenCreation(token);

            return new TokenResponse(
                    HttpServletResponse.SC_OK,
                    "Login successful",
                    token,
                    refreshToken.getToken(),
                    null
            );

        } catch (UsernameNotFoundException | BadCredentialsException e) {
            // Specific handling for failed authentication
            return new TokenResponse(
                    HttpServletResponse.SC_BAD_REQUEST,
                    "User email or password is incorrect",
                    null,
                    null,
                    e.getMessage()
            );
        } catch (AuthenticationException e) {
            // General handling for any other authentication exceptions
            logger.warn(String.valueOf(e));
            return new TokenResponse(
                    HttpStatus.BAD_REQUEST.value(),
                    "Authentication failed",
                    null,
                    null,
                    e.getMessage()
            );
        } catch (Exception e) {
            // Handling for unexpected exceptions
            logger.error("Unexpected error occurred", e);
            return new TokenResponse(
                    HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "Internal server error",
                    null,
                    null,
                    e.getMessage()
            );
        }
    }

    @Override
    public BaseResponse refreshToken(RefreshTokenDto refreshTokenDto) {
        try{
            RefreshToken token = refreshTokenRepo.findByToken(refreshTokenDto.getRefreshToken())
                    .orElseThrow(()-> new RuntimeException("token does not exist"));

            boolean refreshTokenExpired = isRefreshTokenExpired(token);

            if(refreshTokenExpired){
                return new BaseResponse(
                        HttpStatus.FORBIDDEN.value(),
                        "refresh token expired",
                        null,
                        null
                );
            }

            String username = token.getUser().getEmail();

            String accessToken = jwtService.generateAccessTokenUsername(username);

            return new BaseResponse(
                    HttpStatus.OK.value(),
                    "access token generated",
                    accessToken,
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
