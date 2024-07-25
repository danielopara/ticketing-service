package com.projects.Ticketing.service.user.interfaces;

import com.projects.Ticketing.dtos.UserLoginDto;
import com.projects.Ticketing.response.BaseResponse;

public interface UserLogin {
    BaseResponse login(UserLoginDto dto);
}
