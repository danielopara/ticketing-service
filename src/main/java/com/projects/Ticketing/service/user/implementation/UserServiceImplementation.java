package com.projects.Ticketing.service.user.implementation;

import com.projects.Ticketing.dtos.ChangePasswordDto;
import com.projects.Ticketing.dtos.CreateUserDto;
import com.projects.Ticketing.dtos.UpdateDto;
import com.projects.Ticketing.jwt.JwtService;
import com.projects.Ticketing.model.ProfilePhoto;
import com.projects.Ticketing.model.Role;
import com.projects.Ticketing.model.User;
import com.projects.Ticketing.repository.ProfilePhotoRepository;
import com.projects.Ticketing.repository.RoleRepository;
import com.projects.Ticketing.repository.UserRepository;
import com.projects.Ticketing.response.BaseResponse;
import com.projects.Ticketing.service.user.interfaces.UserService;
import com.projects.Ticketing.utils.CompressUtils;
import com.projects.Ticketing.utils.ExtensionRetrieval;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.*;
import java.util.regex.Pattern;

//TODO: User Role and Permissions

@Service
@Slf4j
public class UserServiceImplementation implements UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final ProfilePhotoRepository profilePhotoRepo;
    private final RoleRepository roleRepo;

    @Value("${VALIDATION_EMAIL.regexp}")
    private String emailRegex;

    Logger logger = LoggerFactory.getLogger(UserServiceImplementation.class.getName());

    public UserServiceImplementation(UserRepository userRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, JwtService jwtService, ProfilePhotoRepository profilePhotoRepo, RoleRepository roleRepo) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.profilePhotoRepo = profilePhotoRepo;
        this.roleRepo = roleRepo;
    }

    @Override
    public BaseResponse createUser(CreateUserDto dto) {
        BaseResponse response = new BaseResponse();
        User user = new User();
        try {

            Optional<Role> userRole = roleRepo.findByRoleName(dto.getRole());
            if(userRole.isEmpty()){
                return new BaseResponse(
                        HttpServletResponse.SC_BAD_REQUEST,
                        "role does not exist",
                        dto.getRole(),
                        null
                );
            }

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
//            if (!dto.getRole().equals("ADMIN") && !dto.getRole().equals("USER")) {
//                return new BaseResponse(
//                        HttpServletResponse.SC_BAD_REQUEST,
//                        "roles can either be ADMIN or USER",
//                        null,
//                        null
//                );
//            }

//            Set<Role> roles = new HashSet<>(userRole);
//            roles.add(userRole.get());

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
    public BaseResponse updatePassword(ChangePasswordDto changePasswordDto) {
        try{
            Optional<User> checkUserEmail = userRepository.findByEmail(changePasswordDto.getEmail());

            if(checkUserEmail.isEmpty()){
                return new BaseResponse(
                        HttpStatus.NOT_FOUND.value(),
                        "user not found",
                        null,
                        null
                );
            }

            User user = checkUserEmail.get();
            if(!passwordEncoder.matches(changePasswordDto.getOldPassword(), user.getPassword())){
                return new BaseResponse(
                        HttpStatus.NO_CONTENT.value(),
                        "incorrect old password",
                        null,
                        null
                );
            }

            String encryptedPassword = passwordEncoder.encode(changePasswordDto.getNewPassword());
            user.setPassword(encryptedPassword);
            userRepository.save(user);

            return new BaseResponse(
                    HttpStatus.OK.value(),
                    "password changed successfully",
                    null,
                    null
            );
        } catch (Exception e){
            return new BaseResponse(
                    HttpServletResponse.SC_BAD_REQUEST,
                    "error changing password",
                    null,
                    null
            );
        }
    }

    @Override
    public String addProfilePhoto(Long id, MultipartFile multipartFile) throws IOException {
        if (multipartFile == null || multipartFile.isEmpty()) {
            return "No photo uploaded";
        }

        User user = userRepository.findById(id)
                .orElseThrow(()-> new RuntimeException("User not found"));

        if (profilePhotoRepo.findByUser_Id(id).isPresent()) {
            return "Profile photo exists";
        }


        byte[] fileBytes = multipartFile.getBytes();
        byte[] compressedImage = CompressUtils.compressImage(fileBytes);

        //get file extension
        String fileExtension = ExtensionRetrieval.getFileExtension(multipartFile);

        ProfilePhoto profilePhoto = new ProfilePhoto();
        profilePhoto.setImageData(compressedImage);
        profilePhoto.setFileName(user.getEmail() + "_profilePhoto." + fileExtension);
        profilePhoto.setUser(user);

        profilePhotoRepo.save(profilePhoto);

        return "image added: " + profilePhoto.getFileName();
    }

    @Override
    public String deleteProfilePhotoById(Long id) {
        try{
            Optional<ProfilePhoto> userProfilePhoto = profilePhotoRepo.findByUser_Id(id);

            if(userProfilePhoto.isEmpty()){
                return "no profile photo";
            }

            ProfilePhoto profilePhoto = userProfilePhoto.get();
            profilePhotoRepo.delete(profilePhoto);


            return "Profile photo deleted";
        } catch(Exception e){
            logger.error(e.getMessage());
            return "Error";
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

    @Override
    public byte[] getProfilePhotoById(Long id) {
        Optional<ProfilePhoto> userId = profilePhotoRepo.findByUser_Id(id);

        if(userId.isEmpty()){
            return null;
        }

        ProfilePhoto profilePhoto = userId.get();
        return CompressUtils.decompressImage(profilePhoto.getImageData());
    }
}
