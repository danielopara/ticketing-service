package com.projects.Ticketing.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UpdateDto {
    private String firstName;
    private String lastName;
    private  String phoneNumber;
    private String email;
}
