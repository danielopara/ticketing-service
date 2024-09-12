package com.projects.Ticketing.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TokenResponse {

    private int status;

    private String message;

    private String accessToken;

    private String refreshToken;

    private String error;

}
