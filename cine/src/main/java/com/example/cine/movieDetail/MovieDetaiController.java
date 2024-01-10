package com.example.cine.movieDetail;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MovieDetaiController {
	    
	@GetMapping("movieDetail/movie")
	public String movieDetailMovie() {
		return "movieDetail/movie";
	}
	@GetMapping("movieDetail/comingsoon")
	public String moviecomingsoon() {
		return "movieDetail/comingsoon";
	}
	@GetMapping("movieDetail/movie-detail")
	public String movieDetail() {
		return "movieDetail/movie-detail";
	}
	@GetMapping("movieDetail/movie-detail2")
	public String movieDetail2() {
		return "movieDetail/movie-detail2";
	}
}
