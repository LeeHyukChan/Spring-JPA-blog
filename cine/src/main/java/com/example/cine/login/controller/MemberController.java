package com.example.cine.login.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.example.cine.login.dto.MemberDTO;
import com.example.cine.login.service.MemberService;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;



@Controller
@RequiredArgsConstructor
public class MemberController {
//-------------------------------------------------------------------------------------------------------------------------------------   
   //생성자 주입
   private final MemberService memberService;
//-------------------------------------------------------------------------------------------------------------------------------------






//-------------------------------------------------------------------------------------------------------------------------------------   
   //회원가입 페이지 출력 요청
   
   // 회원가입 페이지로 이동 
   @GetMapping("/member/save")
   public String saveForm() {
      return "login/save";
   }
   
   // 회원가입에서 입력받은 데이터 저장
   @PostMapping("/member/save")
   public String save(@ModelAttribute MemberDTO memberDTO) {
      memberService.save(memberDTO);
      return "/main/cinemain"; // 저장 후 돌아갈 페이지 설정 
   }
//   회원가입 완료
//-------------------------------------------------------------------------------------------------------------------------------------   






//-------------------------------------------------------------------------------------------------------------------------------------
   // ID 중복체크 페이지로 이동 
   @GetMapping("/member/IdCheckForm")
   public String IdCheckForm() {
	      return "/login/IdCheckForm";
   }
   @PostMapping("/member/IdCheck")
   public ResponseEntity<Map<String, Object>> IdCheck(@RequestParam("memId") String memId) {
       boolean isIdAvailable = memberService.isIdAvailable(memId);
       Map<String, Object> response = new HashMap<>();
       System.out.println(isIdAvailable);
       response.put("isIdAvailable", isIdAvailable);
       return ResponseEntity.ok(response);
   }
//   회원가입 중복 체크 
//-------------------------------------------------------------------------------------------------------------------------------------   






//-------------------------------------------------------------------------------------------------------------------------------------   
   @GetMapping("/member/login")
   public String loginForm() {
      return "/login/login";
   }
//-------------------------------------------------------------------------------------------------------------------------------------   






//-------------------------------------------------------------------------------------------------------------------------------------   
//   로그인 페이지 
   @PostMapping("/member/login")
   public String login(@ModelAttribute MemberDTO memberDTO, HttpSession session) {
      MemberDTO loginResult = memberService.login(memberDTO);
      if(loginResult!=null) {
         // login 성공
    	  session.setAttribute("membirth", loginResult.getMemBirth());
          session.setAttribute("loginid", loginResult.getMemId());
          session.setAttribute("memname", loginResult.getMemName());
          session.setAttribute("memphone", loginResult.getMemPhone());
         
         return "/main/cinemain";
      }else {
         // login 실패
         System.out.println("로그인실패");
         return "/login/login";
      }
   }  
 //-------------------------------------------------------------------------------------------------------------------------------------   

   
   
   
   
   
 //-------------------------------------------------------------------------------------------------------------------------------------   

 //-------------------------------------------------------------------------------------------------------------------------------------   






//-------------------------------------------------------------------------------------------------------------------------------------   
//   로그인 완료 시 메인 페이지 실패 시 로그인 페이지.
        
      @GetMapping("/logout")
      public String logout(HttpSession session) {
    	  session.invalidate();
    	  return "/main/cinemain";
      }      
//-------------------------------------------------------------------------------------------------------------------------------------   






//-------------------------------------------------------------------------------------------------------------------------------------  

//    일반 회원  로그아웃

//-------------------------------------------------------------------------------------------------------------------------------------   






//-------------------------------------------------------------------------------------------------------------------------------------         
//      비회원 회원 가입 
      @GetMapping("/nonmember")
      public String nonmemeber() {
    	  return "login/nonmember";
      }
//-------------------------------------------------------------------------------------------------------------------------------------   






}