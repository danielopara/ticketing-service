package com.projects.Ticketing.repository;

import com.projects.Ticketing.model.LogInOutTrail;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TrailRepository extends JpaRepository<LogInOutTrail, Long> {
}
