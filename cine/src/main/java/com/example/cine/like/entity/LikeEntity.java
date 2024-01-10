package com.example.cine.like.entity;

import java.time.LocalDate;

import org.hibernate.annotations.GenericGenerator;

import com.example.cine.login.entity.MemberEntity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Entity
@Table(name = "Likes")
public class LikeEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY, generator = "native")
	@GenericGenerator(name = "native", strategy = "native")
	@Column(name = "id")
	private Long id ;

    @Column(name = "movie_no")
    private int movieNo;
    
    
    @ManyToOne
    @JoinColumn(name = "user_id", referencedColumnName = "MEM_ID")
    private MemberEntity member;


    @Column(name = "like_date")
    private LocalDate likeDate;

    public void setMember(MemberEntity member) {
        this.member = member;
    }
    
    public void setUserId(String userId) {

    }

    // 생성자, 다른 게터, 세터, toString 등...
}