package com.example.cine.movieSeat;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class Mv_seatServiceImp implements Mv_seatService {
	
	@Autowired // 1
	private Mv_seatRepository mv_seatRepository;
	
	@Override
	public Mv_seatEntity updateSeat(Mv_seatEntity mv_seatEntity) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<Mv_seatEntity> getAllSeats() {
		
		return mv_seatRepository.findAll();
	}
	@Override
	public void save(Mv_seatDTO mv_seatDTO) {
		Mv_seatEntity mvSeatEntity = Mv_seatEntity.toMv_seatEntity(mv_seatDTO);
		mv_seatRepository.save(mvSeatEntity);
		
	}
	
	@Override
	public synchronized void saveOrUpdateIfNotExist(String movieName, String playStartTime, String theaterName) {
	    // 먼저 해당 조건으로 이미 데이터가 있는지 확인
		  List<Mv_seatEntity> existingSeats = mv_seatRepository.findByMovietitleAndStarttimeAndTheaterName(movieName, playStartTime, theaterName);

	    if (existingSeats.isEmpty()) {
	        // 데이터가 없으면 새로운 엔터티 생성 및 저장
	    	for (char row = 'a'; row <= 'j'; row++) {
	    	    for (int col = 1; col <= 16; col++) {
	    	        Mv_seatEntity newSeat = new Mv_seatEntity();
	    	        newSeat.setMovietitle(movieName);
	    	        newSeat.setStarttime(playStartTime);
	    	        newSeat.setTheaterName(theaterName);
	    	        newSeat.setSeatrow(String.valueOf(row));
	    	        newSeat.setSeatcol(String.valueOf(col));
	    	        newSeat.setSeatstate("common");
	    	        mv_seatRepository.save(newSeat);
	    	    }
	    	}
	    }
	    else {
	    	return;
	    }
	}
	
	

	@Override
	public void newupdate(Long id) {
		Optional<Mv_seatEntity> optionalEntity = mv_seatRepository.findById(id);
		
		if (optionalEntity.isPresent()) {
		    Mv_seatEntity mvSeatEntity = optionalEntity.get();
		    mvSeatEntity.setSeatstate("finish");
		    mv_seatRepository.save(mvSeatEntity);
		    // mvSeatEntity를 사용하는 코드 작성
		} 
		
	}

	
}
