package com.example.cine.like.controller;

import java.sql.SQLException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.cine.like.entity.LikeEntity;
import com.example.cine.like.service.LikeService;
import com.example.cine.movieSchedule.Mv_scheEntity;

import jakarta.servlet.http.HttpSession;

@RestController
public class LikeControllerJson {
	// private List<LikeDTO> likes = new ArrayList<>();

	@Autowired 
	private LikeService likeService;

	@RequestMapping("/likes")
	  public List<LikeEntity> getAllschedule() throws ClassNotFoundException, SQLException{
		  
		  List<LikeEntity> list = likeService.getAllLikes();
	      return list;
	     
  
	  }
 
  
}