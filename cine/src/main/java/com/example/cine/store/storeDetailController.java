package com.example.cine.store;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class storeDetailController<storeDetail> {
	
	@Autowired
	private final storeService storeService;
	
	public storeDetailController(storeService storeService) {
		this.storeService = storeService;
	}
	
	@RequestMapping("/storeDetail")
	public Optional<storeEntity> storeDetail(@RequestParam("prdtcd") String prdtcd) {
		Optional<storeEntity> list = storeService.getAllInfos(prdtcd);
		return list;
	}
}
