$(document).ready(function() {
	// URL에서 title 파라미터를 가져오기
	var urlParams = new URLSearchParams(window.location.search);
	var titleParameter = urlParams.get("title");
	
	// 관람평 작성 링크 클릭 시 레이어 띄우기
    $(".oneWrtNonMbBtn").on("click", function() {
        // 관람평 레이어 보이기
        $("#layer_regi_reply_review").show();
    });

    // 레이어 닫기 버튼 클릭 시 레이어 닫기
    $(".btn-modal-close, .close-layer").on("click", function() {
        // 관람평 레이어 숨기기
        $("#layer_regi_reply_review").hide();
    });
    
    // 이 부분에 영화 제목과 평점 기능을 추가합니다
    var userRating = 0; // 초기 평점은 0으로 설정

    // 별을 클릭할 때마다 평점을 업데이트
    $(".score .star button").on("click", function() {
        // 클릭한 별의 위치를 가져옴 (1부터 10까지)
        var starValue = $(this).index() + 1;

        // 평점 업데이트
        userRating = starValue;

        // 점수 업데이트
        $(".score .num em").text(userRating);
    });

	// Ajax 요청을 보냅니다.
	$.ajax({
		type: 'GET',
		url: '/movies', // 데이터를 가져오는 URL로 변경
		success: function(data) {
			// URL에서 가져온 title 파라미터와 일치하는 영화 정보 찾기
			var movie = data.find(function(movie) {
				return movie.title === titleParameter;
			});

			if (movie) {
				// 원하는 정보를 추출하여 사용
				var title = movie.title;
				var director = movie.director;
				var actor = movie.actor;

				var spectators = movie.spectators;
				var runtime = movie.runtime;
				var opendate = movie.opendate;
				var imglink = movie.imglink;
				var moviecontent = movie.moviecontent;
				
				// 영화 제목 표시
                $(".score .tit").text('"' + title + '" 영화 어떠셨나요?');

                // 별점 초기화
                $(".score .num em").text(userRating);
				
				var spectClass = '';
				  if (spectators === '전체관람가') {
				      spectClass = "age-all";
				  } else if (spectators === '12세이상관람가') {
				      spectClass = "age-12";
				  } else if (spectators === '15세이상관람가') {
				      spectClass = "age-15";
				  } else if (spectators === '청소년관람불가') {
				      spectClass = "age-19";
				  }

			

				// 추출한 정보를 화면에 출력하거나 다른 작업을 수행
				console.log("영화 제목:", title);
				console.log("감독:", director);
				console.log("출연진:", actor);

			
			} else {
				console.log("해당 영화를 찾을 수 없습니다.");
			}

			// 영화 줄거리를 화면에 추가
			$(".container ").empty();
			var dataMovie = $("<div class=\"movie-detail-page\"><div class=\"bg-img\" style=\"background-image:\"><\/div><div class=\"bg-pattern\"><\/div><div class=\"bg-mask\"><\/div><div class=\"movie-detail-cont\"><p class=\"d-day default\">"+"개봉:"+opendate+"<\/p><p class=\"contents-type\">#돌비시네마<\/p><p class=\"title\">"+
			title+"<\/p><p class=\"title-eng\">"+title+"<\/p><div class=\"btn-util\"><button type=\"button\" title=\"보고싶어 안함\" class=\"btn btn-like\" rpst-movie-no=\"23075200\"><i class=\"iconset ico-heart-line\"><\/i><span title=\"보고싶어 한 명수\" id=\"intrstCnt\">3k<\/span><\/button><div class=\"sns-share\"><a href=\"#\" class=\"btn btn-common-share\" title=\"공유하기\"><i class=\"iconset ico-sns-line\"><\/i> 공유하기<\/a><div class=\"btn-sns-share-wrap\"><div class=\"cont-area\"><div class=\"btn-sns-share-group\"><button type=\"button\" title=\"페이스북 공유하기\" class=\"btn btnSns face\">페이스북<\/button><button type=\"button\" title=\"밴드 공유하기\" class=\"btn btnSns band\">밴드<\/button><button type=\"button\" title=\"트위터 공유하기\" class=\"btn btnSns twitter\">트위터<\/button><button type=\"button\" title=\"링크 공유하기\" class=\"btn btnSns link\">링크공유<\/button><\/div><\/div><\/div><\/div><\/div><div class=\"info\"><div class=\"score\" style=\"display:none;\"><p class=\"tit\">실관람 평점<\/p><div class=\"number gt\" id=\"mainMegaScore\"><p title=\"실관람 평점\" class=\"before\"><em>0<\/em><span class=\"ir\">점<\/span><\/p><\/div><\/div><div class=\"rate\" style=\"padding:0;\"><p class=\"tit\">예매율<\/p><p class=\"cont\"><em>1<\/em>위 (29.1%)<\/p><\/div><div class=\"audience \"><div class=\"tit \"><span class=\"m-tooltip-wrap \">누적관객수<em class=\"m-tooltip ml05\"><i class=\"iconset ico-tooltip-gray\">툴툠보기<\/i><div class=\"m-detail-tooltip\" style=\"display: none; opacity: 1;\"><div class=\"bg-arr bottom\"><\/div><div class=\"cont-area\"><p class=\"reset a-c\">누적관객 및 전일관객은 영화진흥 위원회 영화관 입장권 통합전산망제공 기준입니다.<\/p><\/div><\/div><\/em><\/span><\/div><p class=\"cont\"><em>0<\/em> 명<\/p><\/div><\/div><div class=\"poster\"><div class=\"wrap\"><p class=\"movie-grade "
			+spectClass+"\">"+spectators+"<\/p>"
			+"<img src=\""+imglink+"\" onerror=\"noImg(this)\" alt=\""+title+"\"><a href=\"#\" class=\"btn-poster-down\" title=\"포스터 다운로드\" data-no=\"1172898\" data-sn=\"1\">포스터 다운로드<\/a><\/div><\/div><div class=\"reserve screen-type col-1\"><div class=\"reserve\"><a href=\"../booking/cineReserve?title="+title+"\" class=\"btn reserve\" title=\"영화 예매하기\">예매<\/a><\/div><\/div><\/div>");
			$(".container").html(dataMovie);
			
			$("movie-summary.txt ").empty();
			$(".txt ").html(moviecontent);
			$(".movie-info").empty();
			var movieInfo = "<p>상영타입 : 2D ATMOS(자막), 2D Dolby(자막), 2D(더빙), 2D(자막)</p><div class=\"line\"><p>감독&nbsp;: "
			+director+"</p><p>장르&nbsp;: 애니메이션 / "+runtime+"</p><p>등급:&nbsp; "+spectators+"</p><p>개봉일&nbsp;: 2023.10.25</p><!--           --></div><p>"
			+"출연진&nbsp;: "
			+actor+"</p>";
			$(".movie-info").html(movieInfo);
		},
		error: function() {
			// 요청이 실패한 경우 에러 메시지를 표시할 수 있습니다.
			alert("데이터를 불러오는 중에 오류가 발생했습니다.");
		}
	});
});































