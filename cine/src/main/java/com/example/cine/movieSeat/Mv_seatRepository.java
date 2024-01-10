package com.example.cine.movieSeat;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface Mv_seatRepository extends JpaRepository<Mv_seatEntity, Long>{

	List<Mv_seatEntity> findByMovietitleAndStarttimeAndTheaterName(String movietitle, String starttime, String theaterName);
}
 