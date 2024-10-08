package com.projects.Ticketing.controller;

import com.projects.Ticketing.dtos.ChangePasswordDto;
import com.projects.Ticketing.dtos.CreateUserDto;
import com.projects.Ticketing.dtos.UpdateDto;
import com.projects.Ticketing.response.BaseResponse;
import com.projects.Ticketing.service.user.implementation.UserServiceImplementation;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("api/v1/user")
@Slf4j
public class UserController {
    private final UserServiceImplementation userService;
    Logger logger = LoggerFactory.getLogger(UserController.class.getName());

    public UserController(UserServiceImplementation userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody CreateUserDto dto){
        BaseResponse response = userService.createUser(dto);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        logger.info(String.valueOf(dto));
        if(response.getStatusCode() == HttpServletResponse.SC_OK){
            return new ResponseEntity<>(response, headers, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(response, headers ,HttpStatus.BAD_REQUEST);
        }
    }

    @PutMapping("/update-password")
    public ResponseEntity<?> updatePassword(@RequestBody ChangePasswordDto passwordDto){
        BaseResponse response = userService.updatePassword(passwordDto);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        if(response.getStatusCode() == HttpServletResponse.SC_OK){
            return new ResponseEntity<>(response, headers, HttpStatus.OK);
        }else{
            return new ResponseEntity<>(response, headers, HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/allUsers")
//    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getAllUsers(){
        BaseResponse response = userService.getAllUsers();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        if(response.getStatusCode() == HttpServletResponse.SC_OK){
            return new ResponseEntity<>(response, headers, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(response, headers ,HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("id/{id}")
    public ResponseEntity<?> getUserById(@PathVariable Long id){
        BaseResponse response = userService.getUserById(id);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        if(response.getStatusCode() == HttpServletResponse.SC_OK){
            return new ResponseEntity<>(response, headers, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(response, headers,  HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("email/{email}")
    public ResponseEntity<?> getUserByEmail(@PathVariable String email){
        BaseResponse response = userService.getUserByEmail(email);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        if(response.getStatusCode() == HttpServletResponse.SC_OK){
            return new ResponseEntity<>(response, headers, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(response, headers, HttpStatus.BAD_REQUEST);
        }
    }

    @PutMapping("update/{id}")
    public ResponseEntity<?> updateUserDetails(@PathVariable Long id, @RequestBody UpdateDto dto){
        BaseResponse response = userService.updateUser(id, dto);
        if(response.getStatusCode() == HttpServletResponse.SC_OK){
            return new ResponseEntity<>(response, HttpStatus.OK);
        }else {
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
    }

    @DeleteMapping("delete-user/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id){
        BaseResponse response = userService.deleteUser(id);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        if(response.getStatusCode() == HttpServletResponse.SC_OK){
            return new ResponseEntity<>(response, headers, HttpStatus.OK);
        }else{
            return new ResponseEntity<>(response, headers, HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping(value = "/upload-profilePhoto/{id}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> uploadProfilePhoto(@PathVariable Long id, @RequestParam("file") MultipartFile file){
        try {
            String message = userService.addProfilePhoto(id, file);
            return ResponseEntity.status(HttpStatus.OK).body(message);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to upload file.");
        }
    }

    @GetMapping(value = "get-profilePhoto/{id}")
    public ResponseEntity<?> getProfilePhoto(@PathVariable Long id){
        try{
            byte[] profilePhoto = userService.getProfilePhotoById(id);

            return ResponseEntity.status(HttpStatus.OK)
                    .contentType(MediaType.valueOf("image/png"))
                    .body(profilePhoto);
        }catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to upload file.");
        }
    }

    @DeleteMapping(value = "delete-profilePhoto/{id}")
    public ResponseEntity<?> deleteProfilePhoto(@PathVariable Long id){
        try{
            String response = userService.deleteProfilePhotoById(id);
            return ResponseEntity.status(HttpStatus.OK)
                    .body(response);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to upload file.");
        }
    }
}
