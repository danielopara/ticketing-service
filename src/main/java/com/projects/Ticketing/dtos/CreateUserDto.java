package com.projects.Ticketing.dtos;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
public class CreateUserDto {
    private String firstName;
    private String lastName;
    private String phoneNumber;
    private String email;
    private String role;
    private String password;
}
