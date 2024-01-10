package com.example.cine.login.controller;

import java.sql.SQLException;
import java.util.Optional;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.cine.login.entity.MemberEntity;
import com.example.cine.login.service.MemberService;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;



@RestController
@Controller	
@RequiredArgsConstructor
public class UserInfo {

	

	private final MemberService memberService;
	
	@RequestMapping("/userinfo")
	public Optional<MemberEntity> getAllinfo(@ModelAttribute MemberEntity entity,HttpSession session) throws ClassNotFoundException, SQLException {
		String findId = (String) session.getAttribute("loginid");
		Optional<MemberEntity> list = memberService.allInfo(findId);
		return list;

	}
}
