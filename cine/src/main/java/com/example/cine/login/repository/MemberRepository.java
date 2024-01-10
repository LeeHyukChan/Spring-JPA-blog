package com.example.cine.login.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.cine.login.entity.MemberEntity;
import java.util.List;


public interface MemberRepository extends JpaRepository<MemberEntity, Long>{
   // 아이디로 회원 정보 조회 (select * from member where mem_id=?)
   Optional<MemberEntity> findByEntiMemId(String mem_Id);
   //널방지//
   
}