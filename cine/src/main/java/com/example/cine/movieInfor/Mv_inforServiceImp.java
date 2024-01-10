package com.example.cine.movieInfor;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class Mv_inforServiceImp implements Mv_inforService {

	@Autowired
	private Mv_inforRepository mv_inforRepository;
	
	@Override
	public List<Mv_inforEntity> getAllMovies() {
		// TODO Auto-generated method stub
		return mv_inforRepository.findAll();
	}

}
