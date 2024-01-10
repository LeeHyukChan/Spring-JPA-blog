package com.example.cine.movieInfor;

import java.sql.SQLException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Controller
public class Mv_inforController {

	@Autowired 
	private final Mv_inforService mv_inforService;

	public Mv_inforController(Mv_inforService mv_inforService) {
		this.mv_inforService = mv_inforService;
	}

	@RequestMapping("/movies")
	public List<Mv_inforEntity> getAllschedule() throws ClassNotFoundException, SQLException {
		List<Mv_inforEntity> list = mv_inforService.getAllMovies();
		return list;

	}

}
