package com.projects.Ticketing.controller;

import com.projects.Ticketing.dtos.UserLoginDto;
import com.projects.Ticketing.response.BaseResponse;
import com.projects.Ticketing.service.auth.AuthServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequestMapping("api/v1/auth")
public class AuthController {

    private final AuthServiceImpl authService;

    //logger
    Logger logger = LoggerFactory.getLogger(AuthController.class);

    public AuthController(AuthServiceImpl authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    ResponseEntity<?> login(@RequestBody UserLoginDto userLoginDto){
       BaseResponse response = authService.loginService(userLoginDto);
       if(response.getStatusCode() == HttpStatus.OK.value()){
           return new ResponseEntity<>(response, HttpStatus.OK);
       }else{
           return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
       }
    }

}
