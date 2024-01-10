package com.example.cine.login.entity;

import java.sql.Date;

import com.example.cine.login.dto.MemberDTO;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Setter
@Getter
@Table(name = "MEMBER")
public class MemberEntity {

	
	// 데이터 베이스에서 불러온 값들을 저장하는 객체들 
	
	@Id // PK지정
	@Column(name = "MEM_ID", length = 50)
	private String entiMemId;

	@Column
	private String mem_Pw;

	@Column
	private String mem_Name;

	@Column
	private Date mem_Birth;

	@Column
	private String mem_Phone;

	@Column(unique = true) // UNIQUE 제약조건 추가
	private String mem_Email;

	@Column
	private String mem_Domain;

	@Column
	private int mem_Point;

	@Column
	private Date mem_reg_Date;

	// 2023 10 02 테이블 생성 완료

	public static MemberEntity toMemberEntity(MemberDTO memberDTO) {
		MemberEntity memberEntity = new MemberEntity();
		memberEntity.setEntiMemId(memberDTO.getMemId());
		memberEntity.setMem_Pw(memberDTO.getMemPw());
		memberEntity.setMem_Name(memberDTO.getMemName());
		memberEntity.setMem_Birth(memberDTO.getMemBirth());
		memberEntity.setMem_Phone(memberDTO.getMemPhone());
		memberEntity.setMem_Email(memberDTO.getMemEmail());
		memberEntity.setMem_Domain(memberDTO.getMemDomain());

		return memberEntity;
	}

}