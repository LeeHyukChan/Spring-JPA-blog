$(document).ready(function() {
    // 페이지가 로드될 때 실행되는 함수
	var total=0;
    // Ajax 요청을 보냅니다.
    $.ajax({
        type: 'GET',
        url: '/movies',
        success: function(data) {
            // 요청이 성공하면 데이터를 처리하고 화면에 표시합니다.
            $(".movie-list ol").empty();
            var processedTitles = {};
            var currentIndex = 1; // 순번을 추적하는 변수를 추가
            
            
            
            $.each(data, function(index, item) {
				if (!processedTitles[item.title]){
				console.log(item.title);
				total=total+1;
				
				//item.spectators 값에 따라서 css 클래스 선택
				  var cssClass = '';
				  if (item.spectators === '전체관람가') {
				      cssClass = "age-all";
				  } else if (item.spectators === '12세이상관람가') {
				      cssClass = "age-12";
				  } else if (item.spectators === '15세이상관람가') {
				      cssClass = "age-15";
				  } else if (item.spectators === '청소년관람불가') {
				      cssClass = "age-19";
				  }
				  
				  $("#totCnt").text(total);
				  
				
				       
				
				var movieInfor = $("<li tabindex=\"0\" class=\"no-img\"><div class=\"movie-list-info\">"+
				"<p class=\"rank\" style=\"\">"+ currentIndex +"<span class=\"ir\">위</span></p>"
				+"<img src=\""+item.imglink+"\" "
				+"alt=\""+item.title+"\" class=\"poster lozad\" onerror=\"noImg(this)\"><div class=\"curation\">"
				+"<p class=\"film\" style=\"display: none\">필름 소사이어티</p><p class=\"classic\" style=\"display: none\">"
				+"클래식 소사이어티</p></div><div class=\"screen-type2\"><p name=\"dbcScrean\" style=\"\">"
				+"<img src=\"/static/pc/images/common/btn/mov_top_tag_db.png\" alt=\"dolby\"></p>"
				+"<p name=\"mxScreen\" style=\"\"><img src=\"/static/pc/images/common/btn/mov_top_tag_mx.png\" alt=\"mx\"></p>"
				+"</div><div class=\"movie-score\" style=\"opacity: 0;\">"
				+" <a href=\"/movieDetail/movie-detail?title="+item.title+"\" class=\"wrap movieBtn\" data-no=\"23075200\" "
				+"title=\""+item.title+" 상세보기\"><div class=\"summary\">"
				+item.moviecontent
				+"</div><div class=\"my-score equa\" style=\"display: none;\"><div class=\"preview\"><p class=\"tit\">관람평</p>"
				+"<p class=\"number\">0<span class=\"ir\">점</span></p></div></div></a> </div></div><div class=\"tit-area\">"
				+"<p class=\"movie-grade "+cssClass+"\">,</p><p title=\""+item.title+"\" class=\"tit\">"+item.title+"</p></div>"
				+"<div class=\"rate-date\"> <span class=\"rate\">예매율 0%</span> <span class=\"date\">"+"개봉일 "+ item.opendate.substring(0, 10)+"</span>"
				+"</div><div class=\"btn-util\"> <button type=\"button\" class=\"button btn-like\">"
				+"<i title=\"보고싶어 안함\" class=\"iconset ico-heart-toggle-gray intrstType \"></i><span>0</span></button>"
				+"<p class=\"txt movieStat1\" style=\"display: none\">상영예정</p><p class=\"txt movieStat2\" style=\"display: none\">"
				+"10월 개봉예정</p><p class=\"txt movieStat5\" style=\"display: none\">개봉예정</p>"
				+"<p class=\"txt movieStat6\" style=\"display: none\">상영종료</p><div class=\"case col-2 movieStat3\" style=\"\"> "
				+"<a href=\"#\" class=\"button purple bokdBtn\" data-no=\"23075200\" title=\"영화 예매하기\">예매</a>"
				+" <a href=\"#\" class=\"button purple img splBtn\" data-no=\"23075200\">"
				+"<img src=\"/static/pc/images/common/btn/mov_list_db_btn.png\" alt=\"dolby 버튼\"></a> "
				+"</div><div class=\"case movieStat4\" style=\"display: none\"> <a href=\"#\" class=\"button purple bokdBtn\" data-no=\"23075200\" title=\"영화 예매하기\">예매</a></div></div></li>");
				$(".movie-list ol").append(movieInfor);
				processedTitles[item.title] = true;
				currentIndex++; // 다음 순번으로 이동
				}
				
				$('.movie-list ol li').on({
			        mouseenter : function(){
			            $(this).find('.movie-score').finish().addClass('on').animate({opacity: 1}, 300);
			        },
			        mouseleave : function(){
			            $(this).find('.movie-score').finish().animate({opacity: 0}, 300, function(){
			                $(this).removeClass('on');
			            });
			        },
			        focus : function(){
			            $(this).find('.movie-score').finish().addClass('on').animate({opacity: 1}, 300);
			        },
			        blur : function(){
			            $(this).find('.movie-score').finish().animate({opacity: 0}, 300, function(){
			                $(this).removeClass('on');
			            });
			        }
    });
				})
			
        },
        error: function() {
            // 요청이 실패한 경우 에러 메시지를 표시할 수 있습니다.
            alert("멍청이");
        }
    });
    
    // 검색 버튼 클릭 이벤트 처리
    $("#btnSearch").on("click", function() {
        var searchText = $("#ibxMovieNmSearch").val().toLowerCase();

        // 검색어를 이용하여 영화 목록을 필터링
        $(".movie-list ol li").each(function() {
            var movieTitle = $(this).find(".tit").text().toLowerCase();
            if (movieTitle.indexOf(searchText) > -1) {
                // 검색어를 포함한 영화를 보여줌
                $(this).show();
            } else {
                // 검색어를 포함하지 않은 영화는 숨김
                $(this).hide();
            }
        });

        // 검색 결과 메시지 업데이트
        var visibleMoviesCount = $(".movie-list ol li:visible").length;
        $("#totCnt").text(visibleMoviesCount);
    });
    
    
});