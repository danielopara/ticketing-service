package com.projects.Ticketing.repository;

import com.projects.Ticketing.model.LogInOutTrail;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TrailRepository extends JpaRepository<LogInOutTrail, Long> {
    Optional<LogInOutTrail> findByToken(String token);
}
