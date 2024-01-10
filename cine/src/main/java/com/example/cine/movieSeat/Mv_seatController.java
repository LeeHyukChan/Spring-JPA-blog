package com.example.cine.movieSeat;

import java.sql.SQLException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Controller 
public class Mv_seatController { 
	@Autowired
	private final Mv_seatService mv_seatService;
	
	public Mv_seatController(Mv_seatService mv_seatService)
	{
		this.mv_seatService = mv_seatService;
	}
	
	 
	@RequestMapping("/seats")
	public List<Mv_seatEntity> getAllSeat() throws ClassNotFoundException, SQLException{
	
		List<Mv_seatEntity> list = mv_seatService.getAllSeats();
		return list;
	}

}
