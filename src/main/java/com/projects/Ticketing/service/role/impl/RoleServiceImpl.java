package com.projects.Ticketing.service.role.impl;

import com.projects.Ticketing.model.Role;
import com.projects.Ticketing.repository.RoleRepository;
import com.projects.Ticketing.service.role.interfaces.RoleService;
import org.springframework.stereotype.Service;

@Service
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;

    public RoleServiceImpl(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Override
    public String addRole(String role) {
        if(role.isBlank()){
            return "role cannot be blank";
        }

        Role newRole = new Role();
        newRole.setRoleName(role);

        roleRepository.save(newRole);

        return "role added";
    }
}
