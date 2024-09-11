package com.projects.Ticketing.service.auth;

import com.projects.Ticketing.dtos.RefreshTokenDto;
import com.projects.Ticketing.dtos.UserLoginDto;
import com.projects.Ticketing.response.BaseResponse;
import com.projects.Ticketing.service.auth.refereshToken.RefreshTokenService;

public interface AuthService extends RefreshTokenService {
    BaseResponse loginService(UserLoginDto userLogin);

    BaseResponse refreshToken(RefreshTokenDto refreshTokenDto);
}
