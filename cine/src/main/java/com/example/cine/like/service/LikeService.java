package com.example.cine.like.service;

import java.util.List;

import com.example.cine.like.entity.LikeEntity;

//import com.example.cine.like.entity.LikeEntity;

public interface LikeService {
	//좋아요 처리
    int likeMovie(int movieNo, String userId);
    //int likeMovie(int movieNo, String userId);
    int countBylike(int movieNo);
    // int countBylike(int movieNo);
    
    public List<LikeEntity> getAllLikes();
}