package com.projects.Ticketing.service.auth;

import com.projects.Ticketing.dtos.UserLoginDto;
import com.projects.Ticketing.response.BaseResponse;

public interface AuthService {
    BaseResponse loginService(UserLoginDto userLogin);
}
