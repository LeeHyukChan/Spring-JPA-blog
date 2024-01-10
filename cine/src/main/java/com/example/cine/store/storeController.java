package com.example.cine.store;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class storeController {
	
	@Autowired
	private final storeService storeService;
	
	public storeController(storeService storeService) {
		this.storeService = storeService;
	}
	
	@GetMapping("/store")
	public String store() {
		return "store/cineStore";
	}
	
	@GetMapping("/storeDetailInfo")
	public String storeDetail(@RequestParam("prdtcd") String prdtcd, Model model) {
		Optional<storeEntity> list = storeService.getAllInfos(prdtcd);
		model.addAttribute("list", list);
		return "store/cineStoreDetail";
	}
}
