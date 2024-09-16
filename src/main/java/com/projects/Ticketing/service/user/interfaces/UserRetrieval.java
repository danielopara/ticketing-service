package com.projects.Ticketing.service.user.interfaces;

import com.projects.Ticketing.response.BaseResponse;

public interface UserRetrieval {
    BaseResponse getAllUsers();
    BaseResponse getUserById(Long id);
    BaseResponse getUserByEmail(String email);

    //getting profile photo
    byte[] getProfilePhotoById(Long id);
}
