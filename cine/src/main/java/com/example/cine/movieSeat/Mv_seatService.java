package com.example.cine.movieSeat;

import java.util.List;

public interface Mv_seatService {
	
	Mv_seatEntity updateSeat(Mv_seatEntity mv_seatEntity);

    List<Mv_seatEntity> getAllSeats();
    public void save(Mv_seatDTO mv_seatDTO);
    public void newupdate(Long id);
	void saveOrUpdateIfNotExist(String movieName, String playStartTime,String theaterName);
}
