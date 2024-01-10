
$(document).ready(function() {
	$.ajax({
		type: "GET",
		url: "/movies",
		dataType: 'json',

		success: function(data) {
			console.log("혁찬JS CONSOLE");
			list(data)
		},
		error: function() {

			console.log("에러: ");
		}
	});
});



function likeTotal(id, callback) {
	$.ajax({
		type: "GET",
		url: "/likes",
		dataType: 'json',

		success: function(data) {
			console.log("likeTotal은 됩니다");
			likes(data, id, function(count) {
				callback(count);
			});
		},
		error: function() {
			console.log("에러 발생");
			// 에러 처리 로직 추가
		}
	});
}

function likes(data, id, callback) {
	console.log(data, id);
	var count = 0;
	$.each(data, function(index, item) {
		if (item.movieNo === id) {
			count++;
		}
	});
	console.log(count);
	callback(count); // 결과를 콜백으로 반환
}




function list(data) {
	$(".main-movie-list .list").empty();
	//console.log("&nbsp&nbsp&nbsp="+data );
	$.each(data, function(index, item) {
		if (index < 4) {
			if (index === 0) {
				var rank = "first"
			}
			likeTotal(index + 1, function(likes) {

				var htmlToInsert = "<li name=\"li_boxoRankList\" class=\"" + rank + "\"><a href=\"../movieDetail/movie-detail?title=" + item.title + "\" class=\"movie-list-info\" title=\"영화상세 보기\"><p class=\"rank\">" +
					(index + 1) + "<span class=\"ir\">위</span></p><img src=" + item.imglink + " alt=\"" + item.title + "\" class=\"poster\" onerror=\"noImg(this, 'main');\"><div class=\"wrap\" style=\"display: none; opacity: 1;\"><div class=\"summary\"><br>" + item.moviecontent + "</div><div class=\"score\"><div class=\"preview\"><p class=\"tit\">관람평</p><p class=\"number\">9.3<span class=\"ir\">점</span></p></div></div></div></a><div class=\"btn-util\"><button type=\"button\" class=\"button btn-like\""
					+ "0" + " data-rpst-movie-no=\"" + (index + 1) + "\"><i title=\"보고싶어 설정 안함\" class=\"iconset ico-heart-toggle-gray\"></i>" + ""
					+ likes + "" + "</button><div class=\"case\"><a href=\"../booking/cineReserve;\" class=\"button gblue\" title=\"영화 예매하기\">예매</a></div></div></li>";

				$(".main-movie-list .list").append(htmlToInsert);
			});
		}
	});
}
$(document).on("mouseenter", ".list li", function() {
	$(this).find(".wrap").css("display", "block");
}).on("mouseleave", ".list li", function() {
	$(this).find(".wrap").css("display", "none");
});









/*  영진 좋아요 클릭기능 구현 */


$(document).ready(function() {
	//$(".btn-like").click(function() {
	$(document).on('click', '.btn-like', function() {
		var button = $(this);
		var movieNo = button.data("rpst-movie-no"); // rpst-movie-no 속성의 값을 읽어옴
		console.log(movieNo);
		// 사용자 세션 정보 가져오는 코드
		var userId;
		if ("${session.loginid}") {
			userId = "${session.loginid}";
		} else if ("${session.kakaoemail}") {
			userId = "${session.kakaoemail}";
		}
		
		// Ajax 요청
		$.ajax({
			type: "POST",
			url: "/like",
			data: {
				movieNo: movieNo,
				userId: userId
			},
			success: function(response, status, xhr) {
				console.log("좋아요 요청 성공:", response);
				//좋아요 수 없데이트

				var likeCount = response.likescount;
				//console.log("좋아요 갯수== " + likeCount); 
				if (xhr.status === 200) {
					button.addClass("liked");
					button.html('<i title="보고싶어 설정 안함" class="iconset ico-heart-toggle-gray"></i>' + likeCount);
				} else {
					console.error("좋아요 처리에 실패했습니다.");
				}
			},
			error: function(xhr, status, error) {
				console.error("Ajax 요청 실패 이유는: " + error);
				if (xhr.status === 401) {
					console.log("401401401");
					alert("로그인이 필요한 기능입니다.");
				}
			}
		});
	});
});

/* function fetchPage(name){
fetch(name).then(function(response){
   response.text().then(function(text){
//                                     alert(text); 
	  document.querySelector('article').innerHTML=text;
   });
})
} */

/* 영진 좋아요 기능 구현 */
