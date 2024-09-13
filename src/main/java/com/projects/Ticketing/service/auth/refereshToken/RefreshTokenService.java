package com.projects.Ticketing.service.auth.refereshToken;

import com.projects.Ticketing.model.RefreshToken;


public interface RefreshTokenService {
    RefreshToken createRefreshToken(Long id);
}
