package com.example.cine.movieSchedule;

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
@Table(name="MOVIE_SCHEDULE")
public class Mv_scheEntity {

    @Id 
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name = "BRAND", length = 26)
    private String brand;

    @Column(name = "THEATERNAME", length = 60)
    private String theaterName;

    @Column(name = "THEATERNUM", length = 100)
    private String theaterNum;

    @Column(name = "MOVIETITLE", length = 100)
    private String movieTitle;

    @Column(name = "MOVIERUNTIME", length = 26)
    private String movieRuntime;

    @Column(name = "MOVIEDATE")
    private Long movieDate;

    @Column(name = "MOVIESTARTTIME", length = 26)
    private String movieStartTime;

    @Column(name = "THEATERSEATCNT", length = 26)
    private String theaterSeatCnt;

    // 생성자, Getter, Setter, 그리고 다른 메서드들은 필요에 따라 추가할 수 있습니다.
}