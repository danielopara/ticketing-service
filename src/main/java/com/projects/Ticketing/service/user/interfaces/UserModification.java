package com.projects.Ticketing.service.user.interfaces;

import com.projects.Ticketing.dtos.ChangePasswordDto;
import com.projects.Ticketing.dtos.CreateUserDto;
import com.projects.Ticketing.dtos.UpdateDto;
import com.projects.Ticketing.response.BaseResponse;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

public interface UserModification {
    BaseResponse createUser(CreateUserDto dto);
    BaseResponse updateUser(Long id, UpdateDto dto);
    BaseResponse deleteUser(Long id);
    BaseResponse updatePassword(ChangePasswordDto changePasswordDto);

    //profile photo
    String addProfilePhoto(Long id, MultipartFile multipartFile) throws IOException;
}
