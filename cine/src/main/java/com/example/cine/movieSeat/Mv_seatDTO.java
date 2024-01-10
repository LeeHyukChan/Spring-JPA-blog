package com.example.cine.movieSeat;

import jakarta.persistence.Id;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Setter
@Getter
@NoArgsConstructor
@ToString
public class Mv_seatDTO {
	@Id
	private Long id; // 필요한 경우 ID 필드를 추가
	private String seatcol;
	private String seatrow;
	private String seatstate;
	private String movietitle;
	private String starttime;
	private String theaterName;

	public static Mv_seatDTO toSeatDTO(Mv_seatEntity mv_seatEntity) {
		Mv_seatDTO mv_seatDTO = new Mv_seatDTO();
		mv_seatDTO.setId(mv_seatEntity.getId());
		mv_seatDTO.setSeatcol(mv_seatEntity.getSeatcol());
		mv_seatDTO.setSeatrow(mv_seatEntity.getSeatrow());
		mv_seatDTO.setSeatstate(mv_seatEntity.getSeatstate());
		mv_seatDTO.setMovietitle(mv_seatEntity.getMovietitle());
		mv_seatDTO.setStarttime(mv_seatEntity.getStarttime());
		mv_seatDTO.setTheaterName(mv_seatEntity.getTheaterName());
		return mv_seatDTO;
	}

}
