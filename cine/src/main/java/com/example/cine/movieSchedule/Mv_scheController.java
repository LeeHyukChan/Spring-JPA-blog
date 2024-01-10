package com.example.cine.movieSchedule;

import java.sql.SQLException;
import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Controller
public class Mv_scheController {
	
   
	
    private final Mv_scheService Mv_scheservice;
 
    public Mv_scheController(Mv_scheService Mv_scheservice) {
        this.Mv_scheservice = Mv_scheservice;
    }

// 
//    @RequestMapping(value = "/schedule")
//    public String showSchedule(Model model) {
//        model.addAttribute("schedules", Mv_scheservice.getAllschedule());
//        return "schedule";
//        
//    }

  
    
  @RequestMapping("/schedule")
  public List<Mv_scheEntity> getAllschedule() throws ClassNotFoundException, SQLException{
	  
	  List<Mv_scheEntity> list = Mv_scheservice.getAllschedule();
      return list;
      
  }
  
    
}