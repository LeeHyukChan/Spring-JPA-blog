package com.example.cine.mypage.controller;

import java.sql.Date;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import jakarta.servlet.http.HttpSession;

@Controller
public class MypageController {

    private void SESSION(HttpSession session, Model model) {
          String username = (String) session.getAttribute("loginid");//유저아이디 
          String memname=(String) session.getAttribute("memname"); //유저이름
          Date membirth = (Date) session.getAttribute("membirth"); //유저 생일
          String memphone=(String) session.getAttribute("memphone");//유저 전화번호
          String mememail=(String) session.getAttribute("mememail");//유저 이메일 
          String memdomain=(String) session.getAttribute("memdomain");//유저 도메인
           
          String kakaoname = (String) session.getAttribute("kakaoname"); // 카카오 유저이름
        
          model.addAttribute("loginid", username);
          model.addAttribute("memname", memname);
          model.addAttribute("membirth", membirth);
          model.addAttribute("memphone", memphone);
          model.addAttribute("mememail",mememail);
          model.addAttribute("memdomain",memdomain);
           
        model.addAttribute("kakaoname", kakaoname);
    }

    @GetMapping("/mypage")
    public String mypageform(HttpSession session, Model model) {
        SESSION(session, model);
        return "/mypage/mypage";
    }

    @GetMapping("/mypage/like")
    public String like() {
        return "mypage/like";
    }

    @GetMapping("/mypage/myinfo")
    public String myinfo(HttpSession session, Model model) {
        SESSION(session, model);
        return "mypage/myinfo";
    }
    @GetMapping("/mypage/moviestory")
    public String moviestory(HttpSession session, Model model){
        SESSION(session, model);
        String userId = (String) session.getAttribute("loginid");
    
        return "mypage/moviestory";
    }
    

}