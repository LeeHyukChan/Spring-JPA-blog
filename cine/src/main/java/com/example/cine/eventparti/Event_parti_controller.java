package com.example.cine.eventparti;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.cine.login.dto.MemberDTO;
import com.example.cine.login.service.MemberService;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;


@Controller
@RequiredArgsConstructor
public class Event_parti_controller {
	private final Event_parti_service event_parti_service;
	
	private void SESSION(HttpSession session, Model model) {
 	   	String username = (String) session.getAttribute("loginid");//유저아이디 
        String kakaoname = (String) session.getAttribute("kakaoname"); // 카카오 유저이름
     
        model.addAttribute("loginid", username);    
        model.addAttribute("kakaoname", kakaoname);
	}

//	@GetMapping("/save")
//	public String saveForm() {
//		return "save";
//	}
	
	@GetMapping("eventdetail")
	public String eventdetail(HttpSession session,Model model) {
		SESSION(session, model);
		System.out.println("Session" + model);
		return "event/event_detail";
	}
	
	@PostMapping("eventparti")
	public String save(@ModelAttribute Event_parti_DTO event_parti_DTO) throws IOException{
		System.out.println("event_parti_DTO = " + event_parti_DTO);
		event_parti_service.save(event_parti_DTO);
		return "event/event";

	}
	

}
