package com.projects.Ticketing.controller;

import com.projects.Ticketing.dtos.RefreshTokenDto;
import com.projects.Ticketing.dtos.UserLoginDto;
import com.projects.Ticketing.jwt.JwtService;
import com.projects.Ticketing.response.BaseResponse;
import com.projects.Ticketing.response.TokenResponse;
import com.projects.Ticketing.service.auth.AuthServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@Slf4j
@RequestMapping("api/v1/auth")
public class AuthController {

    private final AuthServiceImpl authService;

    private final JwtService jwtService;



    //logger
    Logger logger = LoggerFactory.getLogger(AuthController.class);

    public AuthController(AuthServiceImpl authService, JwtService jwtService) {
        this.authService = authService;
        this.jwtService = jwtService;
    }

    @PostMapping("/login")
    ResponseEntity<?> login(@RequestBody UserLoginDto userLoginDto){
       TokenResponse response = authService.loginService(userLoginDto);

        HttpHeaders headers = new HttpHeaders();


        ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", response.getRefreshToken())
                .httpOnly(true)
                .secure(true)
                .path("/api")
                .maxAge(7 * 24 * 60 * 60)
                .sameSite("Strict")
                .build();

        headers.add(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        // adding response
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("accessToken", response.getAccessToken());

        //remove the cookie if this is used or remove this if cookie is to be used
        responseData.put("refreshToken", response.getRefreshToken());
        responseData.put("status", response.getStatus());
        responseData.put("message", response.getMessage());


       if(response.getStatus() == HttpStatus.OK.value()){
           return new ResponseEntity<>(responseData, headers, HttpStatus.OK);
       }else{
           return new ResponseEntity<>(response, headers, HttpStatus.BAD_REQUEST);
       }
    }

    @PostMapping("/refresh-token")
    ResponseEntity<?> refreshToken(@RequestBody RefreshTokenDto refreshTokenDto){
        BaseResponse response = authService.refreshToken(refreshTokenDto);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        if(response.getStatusCode() == HttpStatus.OK.value()){
            return new ResponseEntity<>(response, headers, HttpStatus.OK);
        }else{
            return new ResponseEntity<>(response, headers, HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/cookie/refresh-token")
    ResponseEntity<?> cookieToken(@CookieValue(name = "refreshToken") String refreshToken){
        BaseResponse response = authService.refreshTokenCookie(refreshToken);
        if(response.getStatusCode() == HttpStatus.OK.value()){
            return new ResponseEntity<>(response, HttpStatus.OK);
        }else{
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }

    }

    @PostMapping("/logout")
    ResponseEntity<?> logout(HttpServletResponse response, HttpServletRequest request){
        Map<String, Object> message = authService.logOutService(request, response);
        return ResponseEntity.ok(message);
    }

}
