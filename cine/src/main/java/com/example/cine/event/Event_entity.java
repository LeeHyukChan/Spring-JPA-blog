package com.example.cine.event;

import java.sql.Date;

import com.example.cine.event.Event_DTO.Event_DTOBuilder;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Entity
@Setter
@Getter
@Table(name="EVENT_LIST")
public class Event_entity {
	@Id
	@Column(name = "EVENTCODE", length = 30)
	private Long eventCode;
	
	@Column(name = "EVENTTITLE", length = 100)
	private String eventTitle;
	
	@Column(name = "EVENTDATERANGE", length = 60)
	private String eventDateRange;
	
	@Column(name = "EVENTPOSTER", length = 100)
	private String eventPoster;
	
	@Column(name = "EVENTCONTENT", length = 100)
	private String eventContent;
	
	@Builder
	public Event_entity(Long eventCode, String eventTitle, String eventDateRange, String eventPoster, String eventContent) {
		this.eventCode = eventCode;
		this.eventTitle = eventTitle;
		this.eventDateRange = eventDateRange;
		this.eventPoster = eventPoster;
		this.eventContent = eventContent;
	}
	

}
