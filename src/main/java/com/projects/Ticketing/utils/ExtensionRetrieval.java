package com.projects.Ticketing.utils;

import org.springframework.web.multipart.MultipartFile;

public class ExtensionRetrieval {
    public static String getFileExtension(MultipartFile multipartFile) {
        String originalFilename = multipartFile.getOriginalFilename();

        if (originalFilename != null && originalFilename.contains(".")) {
            return originalFilename.substring(originalFilename.lastIndexOf(".") + 1);
        }

        return "";
    }
}
