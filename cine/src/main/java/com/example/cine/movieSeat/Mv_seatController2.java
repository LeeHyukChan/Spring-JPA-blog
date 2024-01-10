package com.example.cine.movieSeat;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller  
public class Mv_seatController2 {
	@Autowired
	private final Mv_seatService mv_seatService2;

	public Mv_seatController2(Mv_seatService mv_seatService2) {
		this.mv_seatService2 = mv_seatService2;
	}

//	@PostMapping("/save")
//	public String save(@ModelAttribute Mv_seatDTO mv_seatDTO) {
//
//		System.out.println(mv_seatDTO);
//		mv_seatService2.save(mv_seatDTO);
//		return "/test";
//
//	}
// 
//	@GetMapping("/save")
//	public String save2() {
//		return "/test";
//	}
	
	@GetMapping("/update")
	public String seatUpdate (@RequestParam(value="numValues") String numValue,@RequestParam(value="movieName") String movie ,Model model)
	{
		String[] parts = numValue.split(",");
		for (String part : parts) 
		{
			if(!part.isEmpty()) 
			{
		        long num = Long.parseLong(part);
		        System.out.println(num);
		        mv_seatService2.newupdate(num);
			}
		}
		//List<Mv_seatDTO> mv_seatDTO = new ArrayList<>();
		return "payment/sendkakao";

	}

	@GetMapping("/seat")     
	 public String cineSeat(
		        @RequestParam("playStartTime") String playStartTime,
		        @RequestParam("movieName") String movieName,
		        @RequestParam("theaterNumber") String theaterNumber,
		        @RequestParam("theaterName") String theaterName,
		        @RequestParam("movieRated") String movieRated,
		        @RequestParam("imglink") String imglink,
		        @RequestParam("today") String today,
		        @RequestParam("day") String day,
		        Model model) {
		        // 여기서 매개변수로 받은 데이터를 처리할 수 있습니다.
		        // 예를 들어, 모델에 데이터를 추가하여 Thymeleaf 템플릿으로 전달할 수 있습니다.
		        model.addAttribute("playStartTime", playStartTime);
		        model.addAttribute("movieName", movieName);
		        model.addAttribute("theaterNumber", theaterNumber);
		        model.addAttribute("theaterName", theaterName);
		        model.addAttribute("movieRated", movieRated);
		        model.addAttribute("imglink", imglink);
		        model.addAttribute("today", today);
		        model.addAttribute("day", day);
		        mv_seatService2.saveOrUpdateIfNotExist(movieName, playStartTime, theaterName);
		         
		        return "booking/seat";
		    }
}
