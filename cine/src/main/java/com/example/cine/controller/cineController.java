package com.example.cine.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class cineController {

	
	@GetMapping("/")
	public String main() {
		return "main/cineMain";
	}

	// 결제
	@GetMapping("payment")
	public String payment() {
		return "payment/payment";
	}
	

	// 카카오api
	@GetMapping("sendkakao")
	public String sendkakao() {
		return "payment/sendkakao";
	}
	
	
	
	
	
	@GetMapping("booking/cineReserve") 
	public String bookingCineReserve() { return "booking/cineReserve"; }
	
	@GetMapping("booking/reserve") 
	public String bookingReserve() { return "booking/reserve"; }
	 
	@GetMapping("mypage/mypage") 
	public String mypageMypage() { return "mypage/mypage"; }
	  
	@GetMapping("login/save") 
	public String loginSave() { return "login/save"; }
	 
	
	
}
