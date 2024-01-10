package com.example.cine.movieSeat;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Setter
@Getter
@Table(name = "MOVIE_SEAT")
public class Mv_seatEntity {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id; // 필요한 경우 ID 필드를 추가

	@Column
	private String seatcol;

	@Column
	private String seatrow;

	@Column
	private String seatstate;

	@Column
	private String movietitle;

	@Column
	private String starttime;
	
	@Column
	private String theaterName;

	public static Mv_seatEntity toMv_seatEntity(Mv_seatDTO mv_seatDTO) {
		Mv_seatEntity mv_seatEntity = new Mv_seatEntity();
		mv_seatEntity.setSeatcol(mv_seatDTO.getSeatcol());
		mv_seatEntity.setSeatrow(mv_seatDTO.getSeatrow());
		mv_seatEntity.setSeatstate(mv_seatDTO.getSeatstate());
		mv_seatEntity.setMovietitle(mv_seatDTO.getMovietitle());
		mv_seatEntity.setStarttime(mv_seatDTO.getStarttime());
		mv_seatEntity.setTheaterName(mv_seatDTO.getTheaterName());
		return mv_seatEntity;
	}

	public static Mv_seatEntity toMv_seatUpdateEntity(Mv_seatDTO mv_seatDTO) {
		Mv_seatEntity mv_seatEntity = new Mv_seatEntity();
		mv_seatEntity.setId(mv_seatDTO.getId());
		mv_seatEntity.setSeatcol(mv_seatDTO.getSeatcol());
		mv_seatEntity.setSeatrow(mv_seatDTO.getSeatrow());
		mv_seatEntity.setSeatstate(mv_seatDTO.getSeatstate());
		mv_seatEntity.setMovietitle(mv_seatDTO.getMovietitle());
		mv_seatEntity.setStarttime(mv_seatDTO.getStarttime());
		mv_seatEntity.setStarttime(mv_seatDTO.getStarttime());
		mv_seatEntity.setTheaterName(mv_seatDTO.getTheaterName());
		return mv_seatEntity;
	}
}
