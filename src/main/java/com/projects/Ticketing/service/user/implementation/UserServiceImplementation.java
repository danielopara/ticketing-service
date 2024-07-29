package com.projects.Ticketing.service.user.implementation;

import com.projects.Ticketing.dtos.CreateUserDto;
import com.projects.Ticketing.dtos.UpdateDto;
import com.projects.Ticketing.dtos.UserLoginDto;
import com.projects.Ticketing.jwt.JwtService;
import com.projects.Ticketing.jwt.RefreshTokenService;
import com.projects.Ticketing.model.RefreshToken;
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

import java.util.*;
import java.util.regex.Pattern;

@Service
@Slf4j
public class UserServiceImplementation implements UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshToken;

    @Value("${VALIDATION_EMAIL.regexp}")
    private String emailRegex;

    Logger logger = LoggerFactory.getLogger(UserServiceImplementation.class.getName());

    public UserServiceImplementation(UserRepository userRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, JwtService jwtService, RefreshTokenService refreshToken) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.refreshToken = refreshToken;
    }

    @Override
    public BaseResponse createUser(CreateUserDto dto) {
        BaseResponse response = new BaseResponse();
        User user = new User();
        try {
            // Log incoming role value
            logger.info("Incoming role value: {}", dto.getRole());

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

            // Email checker
            Optional<User> inputtedEmail = userRepository.findByEmail(dto.getEmail());
            if (inputtedEmail.isPresent()) {
                return new BaseResponse(
                        HttpServletResponse.SC_BAD_REQUEST,
                        "User email already exists",
                        null,
                        null
                );
            }

            // Phone number validation
            if (dto.getPhoneNumber() == null || !dto.getPhoneNumber().matches("\\d{11}")) {
                return new BaseResponse(
                        HttpServletResponse.SC_BAD_REQUEST,
                        "Phone number must be 11 digits long and contain only numbers",
                        null,
                        null
                );
            }

            // Role validation
            if (!dto.getRole().equals("ADMIN") && !dto.getRole().equals("USER")) {
                return new BaseResponse(
                        HttpServletResponse.SC_BAD_REQUEST,
                        "roles can either be ADMIN or USER",
                        null,
                        null
                );
            }

            // Save user details
            user.setFirstName(dto.getFirstName());
            user.setLastName(dto.getLastName());
            user.setEmail(dto.getEmail());
            user.setRole(dto.getRole());
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
            response.setDescription("User created successfully");
            response.setError(null);

            return response;
        } catch (Exception e) {
            logger.error("Unexpected error occurred", e);
            return new BaseResponse(HttpStatus.BAD_REQUEST.value(), "creation failed", null, e.getMessage());
        }
    }

    @Override
    public BaseResponse updateUser(Long id, UpdateDto dto) {
        if (id == null || dto == null) {
            return new BaseResponse(
                    HttpStatus.BAD_REQUEST.value(),
                    "Invalid input data.",
                    null,
                    null);
        }

        // Retrieve and update the user in one go
        User existingUser = userRepository.findById(id).orElse(null);

        if (existingUser == null) {
            return new BaseResponse(
                    HttpStatus.NOT_FOUND.value(),
                    "User not found.",
                    null,
                    null);
        }

        // Update user details
        existingUser.setFirstName(dto.getFirstName());
        existingUser.setLastName(dto.getLastName());
        existingUser.setEmail(dto.getEmail());
        existingUser.setPhoneNumber(dto.getPhoneNumber());
        existingUser.setEmail(dto.getEmail());
        // Update other fields from dto as necessary

        // Save the updated user
        userRepository.save(existingUser);

        return new BaseResponse(
                HttpStatus.OK.value(),
                "User updated successfully.",
                null,
                null);
    }

    @Override
    public BaseResponse deleteUser(Long id) {
        try{
            Optional<User> userId = userRepository.findById(id);
            if(userId.isEmpty()){
                return new BaseResponse(
                        HttpStatus.BAD_REQUEST.value(),
                        "user not found",
                        null,
                        null
                );
            }

            userRepository.deleteById(id);
            return new BaseResponse(
                    HttpServletResponse.SC_OK,
                    "user deleted",
                    null,
                    null
            );
        } catch (Exception e){
            return new BaseResponse(
                    HttpServletResponse.SC_BAD_REQUEST,
                    "failed to delete a user",
                    null,
                    null
            );
        }
    }


    @Override
    public BaseResponse login(UserLoginDto dto) {
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
            String accessToken = jwtService.generateToken(authentication);
            RefreshToken token = refreshToken.createRefreshToken(authentication.getName());

            String mainToken = token.getToken();


            Map<String, Object> responseData = new HashMap<>();
            responseData.put("token", accessToken);
            responseData.put("refreshToken", mainToken);
//            jwtService.extractTokenCreation(token);

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
    public BaseResponse getAllUsers() {
        try{
            List<User> allUsers = userRepository.findAll();

            List<Map<String, Object>> userDetailsList = new ArrayList<>();
            for(User user: allUsers){
                Map<String, Object> userDetails = new HashMap<>();

                userDetails.put("firstName", user.getFirstName());
                userDetails.put("lastName", user.getLastName());
                userDetails.put("email", user.getEmail());
                userDetails.put("phoneNumber", user.getPhoneNumber());

                userDetailsList.add(userDetails);
            }
            return new BaseResponse(
                    HttpServletResponse.SC_OK,
                    "list of users",
                    userDetailsList,
                    null
            );
        }catch (Exception e){
            return new BaseResponse(
                    HttpServletResponse.SC_BAD_REQUEST,
                    "error retriving users",
                    null,
                    null
            );
        }
    }

    @Override
    public BaseResponse getUserById(Long id) {

        try{

            if (id == null) {
                return new BaseResponse(
                        HttpStatus.BAD_REQUEST.value(),
                        "Invalid input data.",
                        null,
                        null);
            }

            Optional<User> userId = userRepository.findById(id);
            if(userId.isEmpty()){
                return new BaseResponse(
                        HttpServletResponse.SC_BAD_REQUEST,
                        "user not found",
                        null,
                        null
                );
            }
            User user = userId.get();
            Map<String, Object> userDetails = new HashMap<>();
            userDetails.put("firstName", user.getFirstName());
            userDetails.put("lastName", user.getLastName());
            userDetails.put("phoneNumber", user.getPhoneNumber());
            userDetails.put("email", user.getEmail());

            return new BaseResponse(
                    HttpServletResponse.SC_OK,
                    "user details",
                    userDetails,
                    null
            );
        } catch (Exception e){
            return new BaseResponse(
                    HttpServletResponse.SC_BAD_REQUEST,
                    "failed to get user",
                    null,
                    null
            );
        }
    }

    @Override
    public BaseResponse getUserByEmail(String email) {
        try{
            if (email == null) {
                return new BaseResponse(
                        HttpStatus.BAD_REQUEST.value(),
                        "Invalid input data.",
                        null,
                        null);
            }

            Optional<User> userId = userRepository.findByEmail(email);
            if(userId.isEmpty()){
                return new BaseResponse(
                        HttpServletResponse.SC_BAD_REQUEST,
                        "user not found",
                        null,
                        null
                );
            }
            User user = userId.get();
            Map<String, Object> userDetails = new HashMap<>();
            userDetails.put("firstName", user.getFirstName());
            userDetails.put("lastName", user.getLastName());
            userDetails.put("phoneNumber", user.getPhoneNumber());
            userDetails.put("email", user.getEmail());

            return new BaseResponse(
                    HttpServletResponse.SC_OK,
                    "user details",
                    userDetails,
                    null
            );
        } catch (Exception e){
            return new BaseResponse(
                    HttpServletResponse.SC_BAD_REQUEST,
                    "failed to get user",
                    null,
                    null
            );
        }
    }
}
