package com.example.cine.login.dto;

import java.sql.Date;

import com.example.cine.login.entity.MemberEntity;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor // 기본생성자 자동생성
@ToString // toString 메서드 자동생성
public class MemberDTO {
//   private Long id;

	// 사용자로부터 입력값을 받아서 저장해두는 객체들
	private String memId;
	private String memPw;
	private String memName;
	private Date memBirth;
	private String memPhone;
	private String memEmail;
	private String memDomain;

	public static MemberDTO toMemberDTO(MemberEntity memberEntity) {
		MemberDTO memberDTO = new MemberDTO();
		memberDTO.setMemId(memberEntity.getEntiMemId());
		memberDTO.setMemPw(memberEntity.getMem_Pw());
		memberDTO.setMemName(memberEntity.getMem_Name());
		memberDTO.setMemPhone(memberEntity.getMem_Phone());
		memberDTO.setMemBirth(memberEntity.getMem_Birth());
		memberDTO.setMemEmail(memberEntity.getMem_Email());
		memberDTO.setMemDomain(memberEntity.getMem_Domain());
		return memberDTO;
	}
}