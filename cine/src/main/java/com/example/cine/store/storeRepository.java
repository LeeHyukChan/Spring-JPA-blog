package com.example.cine.store;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface storeRepository extends JpaRepository<storeEntity, String>{
	storeEntity findByPrdtcd(String prdtcd);
}