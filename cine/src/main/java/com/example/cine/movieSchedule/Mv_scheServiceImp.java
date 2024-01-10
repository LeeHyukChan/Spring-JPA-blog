package com.example.cine.movieSchedule;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import jakarta.persistence.TypedQuery;

@Service
public class Mv_scheServiceImp implements Mv_scheService{
	
	@Autowired
	private Mv_scheRepository mvScheRepository;
	
	@Override
	public List<Mv_scheEntity> getAllschedule() {
		return mvScheRepository.findAll();
	}

	
}