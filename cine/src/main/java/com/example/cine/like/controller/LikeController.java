package com.example.cine.like.controller;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.cine.like.service.LikeService;

import jakarta.servlet.http.HttpSession;

@RestController
public class LikeController {
    //private List<LikeDTO> likes = new ArrayList<>();
	
	@Autowired 
    private LikeService likeService;
    
    @PostMapping("/like")
    public ResponseEntity<Map<String, Object>> like(@RequestParam("movieNo") int movieNo,
    		HttpSession session){
    	  
    	String userId = (String) session.getAttribute("loginid");
        if (userId == null) {
            userId = (String) session.getAttribute("kakaoname");
        }
        //System.out.println("hi2023"); 좋아요 버튼 확인 서버접속 확인
    	System.out.println("movieNo: " + movieNo);// 좋아요 영화 넘버 확인
        System.out.println("userId: " + userId); //좋아요 session 값 확인
        
        
        if (userId == null || userId.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Collections.singletonMap("error", "로그인이 필요한 기능입니다."));
        } //로그인 안되어있을시 alert과 함께 RETURN
        
        // 좋아요 처리 로직 수행
        int likescount = likeService.likeMovie(movieNo, userId);
        // 좋아요 처리 로직 수행
        
    
        
        // JSON 응답 반환
        Map<String, Object> response = new HashMap<>();
        response.put("message", "좋아요가 눌렸습니다.");
        response.put("likescount", likescount);
        return ResponseEntity.ok(response);
    }
   

 
  
}