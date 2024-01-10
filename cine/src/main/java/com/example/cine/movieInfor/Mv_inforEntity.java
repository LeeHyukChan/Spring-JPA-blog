package com.example.cine.movieInfor;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Setter
@Getter
@Table(name="MOVIE")
public class Mv_inforEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id; // 필요한 경우 ID 필드를 추가

    @Column
    private String title;
    
    @Column
    private String director;
    
    @Column
    private String actor;
    
    @Column
    private String genre;
    
    @Column
    private String spectators;
    
    @Column
    private String runtime;
    
    @Column
    private String opendate;
    
    @Column
    private String imglink;
    
    @Column
    private String moviecontent;

    // 생성자, getter 및 setter 메서드 등 필요한 메서드 추가
}