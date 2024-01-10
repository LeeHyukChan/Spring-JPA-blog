package com.example.cine.like.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@ToString
public class LikeDTO {
    private int movieNo; // 좋아요 대상 영화 번호
    private String userId; // 좋아요 한 유저 식별자 (MEM_ID)
    private int likeCount; // 좋아요 수
    private String likeDate; // 좋아요 체크한 날짜
}