package com.example.cine.like.service;

import java.time.LocalDate;
import java.util.List;

import org.springframework.stereotype.Service;

import com.example.cine.like.entity.LikeEntity;
import com.example.cine.like.repository.LikeRepository;
import com.example.cine.login.entity.MemberEntity;

@Service
public class LikeServiceImpl implements LikeService {

    private final LikeRepository likeRepository;
    
    
    public LikeServiceImpl(LikeRepository likeRepository) {
        this.likeRepository = likeRepository;
    }

    @Override
    public int likeMovie(int movieNo, String userId) {
    	int likescount = 0;
    	System.out.println("service likeMovie");
    	System.out.println(movieNo + userId);
    	LocalDate currentDate = LocalDate.now();
    	// 좋아요 처리 로직을 구현
    	// 1. 이미 좋아요한 내역이 있는지 확인
    	LikeEntity existingLike = likeRepository.findByMovieNoAndMember_EntiMemId(movieNo, userId);
    	LikeEntity newLike = new LikeEntity();
    	System.out.println("좋아요 처리 시작= " + likescount);
        if (existingLike == null) {
            System.out.println("Liking the movie...");
            System.out.println(movieNo);
            
            newLike.setMovieNo(movieNo);
            // MemberEntity를 생성하고 userId 설정
            MemberEntity memberEntity = new MemberEntity();
            memberEntity.setEntiMemId(userId);
            // newLike 객체에 MemberEntity 설정
            newLike.setMember(memberEntity);//좋아요 id
            newLike.setLikeDate(currentDate);//좋아요 날짜
            likeRepository.save(newLike);
        }else {
        	System.out.println("삭제 처리 시작");
        	likeRepository.delete(existingLike);
        }
        likescount =likeRepository.countByMovieNo(movieNo);
        System.out.println("좋아요 갯수= " + likescount);
        return likescount;
        //프론트 넘기고.
    }

	@Override
	public int countBylike(int movieNo) {
		return likeRepository.countByMovieNo(movieNo);
	}

	@Override
	public List<LikeEntity> getAllLikes() {
		// TODO Auto-generated method stub
		return likeRepository.findAll();
	}



	
	

	




}