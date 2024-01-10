package com.example.cine.event;


import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@ToString

public class Event_DTO {
	private Long eventCode;
	private String eventTitle;
	private String eventDateRange;
	private String eventPoster;
	private String eventContent;

	public Event_entity toEntity() {
		Event_entity build = Event_entity.builder()
				.eventCode(eventCode)
				.eventTitle(eventTitle)
				.eventDateRange(eventDateRange)
				.eventPoster(eventPoster)
				.eventContent(eventContent)
				.build();
		
		return build;
		
	}

	@Builder
	public Event_DTO(Long eventCode, String eventTitle, String eventDateRange, String eventPoster, String eventContent) {
		this.eventCode = eventCode ;
		this.eventTitle = eventTitle ;
		this.eventDateRange = eventDateRange ;
		this.eventPoster = eventPoster ;
		this.eventContent = eventContent ;
		
	}

}
