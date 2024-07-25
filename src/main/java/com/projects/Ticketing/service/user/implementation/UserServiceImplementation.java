package com.projects.Ticketing.service.user.implementation;

import com.projects.Ticketing.controller.UserController;
import com.projects.Ticketing.dtos.CreateUserDto;
import com.projects.Ticketing.dtos.UserLoginDto;
import com.projects.Ticketing.jwt.JwtAuthService;
import com.projects.Ticketing.jwt.JwtService;
import com.projects.Ticketing.model.Roles;
import com.projects.Ticketing.model.User;
import com.projects.Ticketing.repository.UserRepository;
import com.projects.Ticketing.response.BaseResponse;
import com.projects.Ticketing.service.user.interfaces.UserService;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

@Service
@Slf4j
public class UserServiceImplementation implements UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final JwtAuthService jwtAuthService;

    @Value("${VALIDATION_EMAIL.regexp}")
    private String emailRegex;

    Logger logger = LoggerFactory.getLogger(UserServiceImplementation.class.getName());

    public UserServiceImplementation(UserRepository userRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, JwtService jwtService, JwtAuthService jwtAuthService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.jwtAuthService = jwtAuthService;
    }

    @Override
    public BaseResponse createUser(CreateUserDto dto) {
        BaseResponse response = new BaseResponse();
        User user = new User();
        try {
            // Email validation
            Pattern pattern = Pattern.compile(emailRegex);
            if (dto.getEmail() == null || !pattern.matcher(dto.getEmail()).matches()) {
                return new BaseResponse(
                        HttpServletResponse.SC_BAD_REQUEST,
                        "Invalid email format",
                        null,
                        null
                );
            }

            //email checker
            Optional<User> inputtedEmail = userRepository.findByEmail(dto.getEmail());
            if (inputtedEmail.isPresent()) {
                return new BaseResponse(
                        HttpServletResponse.SC_BAD_REQUEST,
                        "user email already exist",
                        null,
                        null
                );
            }

            //phone number validation
            if (dto.getPhoneNumber() == null || !dto.getPhoneNumber().matches("\\d{11}")) {
                return new BaseResponse(
                        HttpServletResponse.SC_BAD_REQUEST,
                        "Phone number must be 11 digits long and contain only numbers",
                        null,
                        null
                );
            }

            //adding roles
            if (Objects.equals(dto.getRole(), Roles.ADMIN.name())) {
                user.setRole(Roles.ADMIN);
            } else if (Objects.equals(dto.getRole(), Roles.USER.name())) {
                user.setRole(Roles.USER);
            } else {
                return new BaseResponse(
                        HttpServletResponse.SC_BAD_REQUEST,
                        "User role can only be ADMIN or USER",
                        null,
                        null
                );
            }

            // saving the dto
            user.setFirstName(dto.getFirstName());
            user.setLastName(dto.getLastName());
            user.setEmail(dto.getEmail());
            user.setPhoneNumber(dto.getPhoneNumber());
            user.setPassword(passwordEncoder.encode(dto.getPassword()));

            Map<String, Object> userDetail = new HashMap<>();

            userDetail.put("firstName", dto.getFirstName());
            userDetail.put("lastName", dto.getLastName());
            userDetail.put("email", dto.getEmail());
            userDetail.put("phoneNumber", dto.getPhoneNumber());


            userRepository.save(user);

            response.setData(userDetail);
            response.setStatusCode(HttpServletResponse.SC_OK);
            response.setDescription("user created");
            response.setError(null);

            return response;
        } catch (Exception e) {
            return new BaseResponse(HttpStatus.BAD_REQUEST.value(), "Authentication Failed", null, e.getMessage());
        }
    }

    @Override
    public BaseResponse login(UserLoginDto dto) {
        try {
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
            Map<String, Object> claims = new HashMap<>();
            String token = jwtService.generateToken(claims, authentication);

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("token", token);
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
}
