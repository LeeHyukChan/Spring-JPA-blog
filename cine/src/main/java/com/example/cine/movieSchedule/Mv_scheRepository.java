package com.example.cine.movieSchedule;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface Mv_scheRepository extends JpaRepository<Mv_scheEntity, Long> {
    // 추가적인 메소드나 쿼리 메소드를 필요에 따라 정의할 수 있습니다.

    // 브랜드(brand)에 따라 스케줄 목록을 가져오는 메소드
    List<Mv_scheEntity> findByMovieTitleAndTheaterName(String movieTitle, String theaterName);

}
 