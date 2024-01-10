package com.example.cine.eventparti;


import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@Table(name="EVENT_PARTI")
public class Event_parti_entity {
	
	@Id
	@Column
	private String EVENTPARTIID;
	
	@Column
	private Long EVENTCODE;

	@Column
	private String EVENTTITLE;

	
	public static Event_parti_entity toEvent_parti_entity(Event_parti_DTO event_parti_DTO) {
		Event_parti_entity event_parti_entity = new Event_parti_entity();
		event_parti_entity.setEVENTPARTIID(event_parti_DTO.getEventPartiId());
		event_parti_entity.setEVENTCODE(event_parti_DTO.getEventCode());
		event_parti_entity.setEVENTTITLE(event_parti_DTO.getEventTitle());
		
		return event_parti_entity;
		
	}


	

}
