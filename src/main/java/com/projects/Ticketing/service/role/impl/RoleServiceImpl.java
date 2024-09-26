package com.projects.Ticketing.service.role.impl;

import com.projects.Ticketing.model.Role;
import com.projects.Ticketing.repository.RoleRepository;
import com.projects.Ticketing.service.role.interfaces.RoleService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class RoleServiceImpl implements RoleService {

    private static final Logger logger = LoggerFactory.getLogger(RoleServiceImpl.class);


    private final RoleRepository roleRepository;

    public RoleServiceImpl(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Override
    public String addRole(String role) {
        try {

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            System.out.println("Roles: " + authentication.getAuthorities());
            logger.info(authentication.getAuthorities().toString());

            if (role.isBlank()) {
                return "Role cannot be blank";
            }


            Role newRole = new Role();
            newRole.setRoleName(role);


            roleRepository.save(newRole);

            return "Role added";
        } catch (AccessDeniedException e) {
            logger.error("Access denied: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.error("Error adding role: {}", e.getMessage());
            return "Error";
        }
    }
}
