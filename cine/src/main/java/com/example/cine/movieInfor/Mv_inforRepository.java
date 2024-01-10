package com.example.cine.movieInfor;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface Mv_inforRepository extends JpaRepository<Mv_inforEntity, Long> {
	
}
