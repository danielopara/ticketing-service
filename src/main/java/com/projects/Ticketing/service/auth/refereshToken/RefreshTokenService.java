package com.projects.Ticketing.service.auth.refereshToken;

import com.projects.Ticketing.model.RefreshToken;

import java.util.Optional;

public interface RefreshTokenService {
    RefreshToken createRefreshToken(Long id);
}
