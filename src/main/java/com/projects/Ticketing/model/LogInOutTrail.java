package com.projects.Ticketing.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "login_logout_trail")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class LogInOutTrail {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String token;

    @ManyToOne
    @JoinColumn(name = "email", referencedColumnName = "id", nullable = false)
    private User user;

    private LocalDateTime loginTime;

    private LocalDateTime logoutTime;
}
