package com.example.cine.eventparti;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import lombok.*;

@Service
@RequiredArgsConstructor 
public class Event_parti_service {
	
	private final Event_parti_repository event_parti_repository;

    
	
	public void save(Event_parti_DTO event_parti_DTO) {
		System.out.println(event_parti_DTO);
		Event_parti_entity event_parti_entity = Event_parti_entity.toEvent_parti_entity(event_parti_DTO);
		System.out.println("영진"+ event_parti_entity);
		event_parti_repository.save(event_parti_entity);
	}

}
