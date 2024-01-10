package com.example.cine.store;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class storeService {
	
	@Autowired
	private storeRepository storeRepository;
	
	public Optional<storeEntity> getAllInfos(String prdtcd) {
		return storeRepository.findById(prdtcd);
	}
}
