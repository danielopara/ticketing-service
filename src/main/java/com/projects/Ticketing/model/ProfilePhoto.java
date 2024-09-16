package com.projects.Ticketing.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "profile_photo")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ProfilePhoto {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long id;

    @Column(name = "file_name")
    private String fileName;

    @Column(name = "image_data", columnDefinition = "LONGBLOB")
    @Lob
    private byte[] imageData;


    @OneToOne
    @JoinColumn(name = "user_id")
    private User user;
}
