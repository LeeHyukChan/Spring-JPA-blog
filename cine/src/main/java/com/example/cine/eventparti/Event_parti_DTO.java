package com.example.cine.eventparti;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;



@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class Event_parti_DTO {
	private Long eventCode;
	private String eventTitle;
	private String eventPartiId;
	
	public static Event_parti_DTO toEvent_parti_DTO(Event_parti_entity event_parti_entity) {
		Event_parti_DTO event_parti_DTO = new Event_parti_DTO();
		event_parti_DTO.setEventPartiId(event_parti_entity.getEVENTPARTIID());
		event_parti_DTO.setEventCode(event_parti_entity.getEVENTCODE());
		event_parti_DTO.setEventTitle(event_parti_entity.getEVENTTITLE());
		return event_parti_DTO;
		
	}
	
}
