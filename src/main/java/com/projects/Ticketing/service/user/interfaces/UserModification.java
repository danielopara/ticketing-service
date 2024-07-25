package com.projects.Ticketing.service.user.interfaces;

import com.projects.Ticketing.dtos.CreateUserDto;
import com.projects.Ticketing.response.BaseResponse;

public interface UserModification {
    BaseResponse createUser(CreateUserDto dto);
}
