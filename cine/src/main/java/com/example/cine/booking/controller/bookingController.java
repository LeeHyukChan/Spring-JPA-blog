package com.example.cine.booking.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class bookingController{
	 

	@GetMapping("/cineReserve")	
	public String cineReserve() {
		return "booking/cineReserve";
	}
	@GetMapping("/reserve")	
	public String reserve() {
		return "booking/reserve";
	}
	
	
	

	
	
}