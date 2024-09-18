package com.projects.Ticketing.controller;

import com.projects.Ticketing.service.role.impl.RoleServiceImpl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/role")
public class RoleController {

    private final RoleServiceImpl roleService;

    public RoleController(RoleServiceImpl roleService) {
        this.roleService = roleService;
    }

    @PostMapping("/addRole")
    public ResponseEntity<?> addRole(@RequestBody String role){
        String userRole = roleService.addRole(role);
        return ResponseEntity.status(HttpStatus.OK).body(userRole);
    }
}
