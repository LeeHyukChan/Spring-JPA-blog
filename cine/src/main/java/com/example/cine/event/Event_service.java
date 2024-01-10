package com.example.cine.event;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;

@Service
public class Event_service {
	
	private Event_repository event_repository;
	
	public Event_service(Event_repository event_repository) {
		this.event_repository = event_repository;
	}
	
	public List<Event_DTO> getEventList() {
		List<Event_entity> eventList = event_repository.findAll();
		List<Event_DTO> eventDtoList = new ArrayList<>();
		
		for(Event_entity event_entity : eventList) {
			Event_DTO event_DTO = Event_DTO.builder()
					.eventCode(event_entity.getEventCode())
					.eventTitle(event_entity.getEventTitle())
					.eventDateRange(event_entity.getEventDateRange())
					.eventPoster(event_entity.getEventPoster())
					.eventContent(event_entity.getEventContent())
					.build();
			eventDtoList.add(event_DTO);
		}
		
		return eventDtoList;
	}
	

}
