package com.example.cine.event;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface Event_repository extends JpaRepository<Event_entity,Long> {
	
}
