package com.projects.Ticketing.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class BaseResponse {
    private int statusCode;
    private String description;
    private Object data;
    private Object error;
}
