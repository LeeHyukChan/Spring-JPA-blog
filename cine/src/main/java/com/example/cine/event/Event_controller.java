package com.example.cine.event;

import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor

public class Event_controller {
	
	private Event_service event_service;
	
	public Event_controller(Event_service event_service) {
		this.event_service = event_service ;
	}
	
	private void SESSION(HttpSession session, Model model) {
 	   	String username = (String) session.getAttribute("loginid");//유저아이디 
        String kakaoname = (String) session.getAttribute("kakaoname"); // 카카오 유저이름
     
        model.addAttribute("loginid", username);    
        model.addAttribute("kakaoname", kakaoname);
	}

	@RequestMapping("event")
	public String event(Model model) {
		return "event/event";
	}
	
	@GetMapping("eventList")
	public String eventList(Model model) {
		List<Event_DTO> eventDtoList = event_service.getEventList();
		model.addAttribute("eventList",eventDtoList);
		return "event/event";
		
	}
	
	@GetMapping("eventlogin")
	public String eventdetail(HttpSession session,Model model) {
		SESSION(session, model);
		return "event/event_detail";
	}
	

}
