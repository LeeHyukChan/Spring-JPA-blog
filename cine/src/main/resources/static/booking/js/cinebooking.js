

$(document).ready(function() {
   // 클릭 이벤트를 사용하여 버튼을 클릭하면 데이터를 불러옴
   
   
   // AJAX를 사용하여 JSON 데이터를 가져옴
   $.ajax({
      type: "GET",
      url: '/movies', // 실제 서버 엔드포인트로 대체
      dataType: 'json',
 
      success: function(data) {
         // JSON 데이터를 HTML에 표시
         movie(data);
      },
      error: function() {
         alert('MovieJSON 파일을 불러오는 중 오류가 발생했습니다.');
      }
   });
});



function movie(data) {
   // JSON 데이터를 HTML에 표시
   $("#mCSB_1_container ul").empty();
   $.each(data, function(index, item) {
      var grade;
      grade = item.spectators.substring(0, 2);
      if (grade != 12 && grade != 15 && grade != 18) {
         grade = "all";
      }
      var row = $("<li>");
      row.html("<button type=\"button\" class=\"btn\" movie-nm=\"" + item.title + "\" movie-no=\"23069600\"img-path=\""
      +item.imglink+"\" movie-popup-at=\"N\" movie-popup-no=\"0\" form-at=\"Y\"><span class=\"movie-grade small age-" + grade + "\">" + item.spectators + "</span><i class=\"iconset ico-heart-small\">보고싶어 설정안함</i><span class=\"txt\">" + item.title + "</span></button></li>")
      $("#mCSB_1_container ul").append(row);
   })
}

$(document).on('click', '.date-area .wrap button', function() {
   // 현재 클릭한 버튼에 "on" 클래스 추가
   $(this).addClass('on');

   // 다른 버튼에서 "on" 클래스 제거
   $('.date-area .wrap button').not(this).removeClass('on');
   
   // 세션에 날짜 저장 
   var movieDate = $(this).children('span:first').text() + $(this).find('em').text();
   sessionStorage.setItem("movieDate", movieDate);
   console.log(sessionStorage.getItem("movieDate"))
   
});

$(document).on('click', '.quick-reserve-area .list-area .btn-tab', function() {
   $(this).closest('.list-area').find('.btn-tab').removeClass('on');
   $(this).addClass('on');
   $(this).closest('.list-area').find('.list').hide();
   $(this).next('.list').show();

});



// 예매 - 빠른예매 - 영화 선택
$(document).on('click', '.quick-reserve-area .movie-choice .list .btn', function() {
   $(this).addClass('on');
   $('.quick-reserve-area .movie-choice .list .btn').not(this).removeClass('on')
   
   
   
   // 세션에 영화 이름 저장
   var movieName = $(this).find('.txt').text();
   sessionStorage.setItem("movieName", movieName);
   console.log(sessionStorage.getItem("movieName"))
   
});



// 예매 - 빠른예매 - 영화관 메인 지역 선택
$(document).on('click', '.quick-reserve-area .theater-choice .list .btn', function() {
   $(this).closest('ul').find('.btn').removeClass('on');
   $(this).addClass('on');
   $(this).closest('ul').find('.depth').removeClass('on');
   $(this).next('.depth').addClass('on');
   
   
   // 세션에 지역1 저장
   var movieArea = $(this).find('.txt').text();
   sessionStorage.setItem("movieArea", movieArea);
   console.log(sessionStorage.getItem("movieArea"))

});

// 예매 - 빠른예매 - 영화관 서브 지역 선택
$(document).on('click', '.quick-reserve-area .theater-choice .list .depth button', function() {
   $(this).addClass('on');
   $('.quick-reserve-area .theater-choice .list .depth button').not(this).removeClass('on')
   $('.quick-reserve-area .movie-schedule-area .no-result').css('display', 'none');
   
   
   // 세션에 지역2 저장
   var movieArea2 = $(this).text();
   sessionStorage.setItem("movieArea2", movieArea2);
   console.log(sessionStorage.getItem("movieArea2"))
   
});

// 예매 - 빠른예매 - 영화 시간 선택
$(document).on('click', '.quick-reserve-area .movie-schedule-area .result .scroll ul li .btn', function() {
   $(this).closest('ul').find('.btn').removeClass('on');
   $(this).addClass('on');
   
   
   // 세션에 영화 시간 저장
   var movieTime = $(this).find(".time>strong").text();
   sessionStorage.setItem("movieTime", movieTime);
   console.log(sessionStorage.getItem("movieTime"))
   
   
   
});
// 예매 - 상영시간표
$(document).on('click', '.time-table-page .movie-choice-area .wrap .list-section .scroll .list li .btn', function(e) {
   e.preventDefault();
   $(this).closest('ul').find('.btn').removeClass('on');
   $(this).addClass('on');
});

//스케줄 함수
function schedule(data, location) {
   // 이전 데이터를 지웁니다.
   $("#mCSB_26_container ul").empty();
   // JSON 데이터를 반복하고 표시합니다.
   var uniqueTimes = []; 
   $.each(data, function(index, item) {
      var row = $("<li>");
      // && item.movieTitle.includes($("#mCSB_1_container .on").attr("movie-nm")
      if (item.theaterName.includes(location.substring(0,2))) {
         if (item.movieTitle.includes($("#mCSB_1_container .on").attr("movie-nm"))&& !uniqueTimes.includes(item.movieStartTime)) {
			  uniqueTimes.push(item.movieStartTime);
            row.html("<button type=\"button\" class=\"btn \" id=\"2310131372102\" play-start-time=\"1215\" play-de=\"20231013\" play-seq=\"3\" "
               + "rpst-movie-no=\"23069601\" brch-no=\"1372\" theab-no=\"07\" play-schdl-no=\"2310131372102\" netfnl-adopt-at=\"N\" "
               + "rest-seat-cnt=\"102\" ctts-ty-div-cd=\"MVCT01\" theab-popup-at=\"Y\" theab-popup-no=\"1060\"> "
               + "<div class=\"legend\"></div> "
               + "<span class=\"time\"> "
               + "<strong title=\"상영 시작\">" + item.movieStartTime + "</strong> "
               + "<em title=\"상영 종료\"></em> "
               + "</span><span class=\"title\"> "
               + "<strong title=\"30일\">" + item.movieTitle + "</strong> "
               + "<em>2D</em> "
               + "</span> "
               + "<div class=\"info\"> "
               + "<span class=\"theater\" title=\"극장\">CineLifnk" + location + "<br></span> "
               + "<span class=\"seat\"> "
               + "<strong class=\"now\" title=\"잔여 좌석\"></strong><span>/"
               + "<em class=\"all\" title=\"전체 좌석\"></em></span></span></div> "
               + "</button></li>");
            $(".result .mCSB_container ul").append(row);
         }

      }

   });
}

// 예매 - 영화 선택시 만약 극장이 선택되어 있다면 DB에서 영화 schedule 가져오기    
$(document).on('click', '#mCSB_1_container ul li button', function() {
   if (true) {
      var location = $("#mCSB_4_container .on").text();
         /*console.log(location);*/
      $.ajax({
         type: "GET",
         url: "/schedule",
         dataType: "json",
         success: function(data) {
            // JSON 데이터를 처리하고 표시합니다.
            schedule(data, location);
         },
         error: function() {
            $(".title strong").html("데이터를 가져오는 중 오류가 발생했습니다.");
         }
      });
   }
})

// 예매 - 극장 선택 시 영화관 schedule DB에서 가져오기 1.영화가 선택 되었을 때
$(document).on('click', '#mCSB_4_container ul li button', function() {
   var location = $(this).text();

   $.ajax({
      type: "GET",
      url: "/schedule",
      dataType: "json",
      success: function(data) {
         // JSON 데이터를 처리하고 표시합니다.
         schedule(data, location);
      },
      error: function() {
         $(".title strong").html("데이터를 가져오는 중 오류가 발생했습니다.");
      }
   });

})

$(document).on('click', '#mCSB_26_container ul li button', function() {
   // 클릭한 버튼의 속성들을 가져옵니다.
   var playStartTime = $(this).find(".time strong").text();
   var movieName = $(this).find(".title strong").text(); // 영화 이름을 추출하는 예시
   var theaterNumber = $(this).find(".theater").text().trim();
   var theaterName = theaterNumber.split('\n')[0]; // 극장 이름을 추출하는 예시
   var movieRated = $(".mCSB_container .on").find('span').attr('class');
   var imglink = $(".mCSB_container .on").attr('img-path');
   var today = $("#formDeList .on").attr("date-data");
   var day = $("#formDeList .on .day-kr").text()
   // Booking URL을 동적으로 생성합니다.
   var bookingURL = "/seat?playStartTime=" + playStartTime
      + "&movieName=" + movieName
      + "&theaterNumber=" + theaterNumber
      + "&theaterName=" + theaterName
      + "&movieRated=" + movieRated
      + "&imglink=" + imglink
      + "&today="+today
      + "&day="+day;
   window.location.href = bookingURL;
});



