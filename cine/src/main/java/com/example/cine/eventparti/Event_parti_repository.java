package com.example.cine.eventparti;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.cine.login.entity.MemberEntity;

@Repository
public interface Event_parti_repository extends JpaRepository<Event_parti_entity,Long>{
	 Optional<Event_parti_entity> findByEVENTPARTIID(String eventPartiId );
}
