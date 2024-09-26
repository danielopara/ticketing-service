package com.projects.Ticketing.controller;

import com.projects.Ticketing.dtos.RoleDto;
import com.projects.Ticketing.service.role.impl.RoleServiceImpl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("api/v1/admin/role")
public class RoleController {

    private final RoleServiceImpl roleService;

    public RoleController(RoleServiceImpl roleService) {
        this.roleService = roleService;
    }

    @PostMapping("/addRole")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<?> addRole(@RequestBody RoleDto roleName){
        String userRole = roleService.addRole(roleName.getRole());
        return ResponseEntity.status(HttpStatus.OK).body(userRole);
    }
}
