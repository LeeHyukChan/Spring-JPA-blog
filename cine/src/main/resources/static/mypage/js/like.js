


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
    console.log(item.member.entiMemId);
    console.log($("#contents #contents").text()===item.member.entiMemId);
  });
  console.log(count);
  callback(count); // 결과를 콜백으로 반환
}




function list(data) {
	$(".my-reserve-history").empty();
	//console.log("&nbsp&nbsp&nbsp="+data );
	$.each(data, function(index, item) {
		if (index < 4) 
		{
			if (index === 0) 
			{
				var rank = "first"
			}
			 likeTotal(index + 1, function(likes) {

			var htmlToInsert = "<li name=\"li_boxoRankList\" class=\"" + rank + "\"><a href=\"../movieDetail/movie-detail2?title=" + item.title + "\" class=\"movie-list-info\" title=\"영화상세 보기\"><p class=\"rank\">" +
				(index + 1) + "<span class=\"ir\">위</span></p><img src=" + item.imglink + " alt=\"" + item.title + "\" class=\"poster\" onerror=\"noImg(this, 'main');\"><div class=\"wrap\" style=\"display: none; opacity: 1;\"><div class=\"summary\"><br>" + item.moviecontent + "</div><div class=\"score\"><div class=\"preview\"><p class=\"tit\">관람평</p><p class=\"number\">9.3<span class=\"ir\">점</span></p></div></div></div></a><div class=\"btn-util\"><button type=\"button\" class=\"button btn-like\"" 
				+ "0" + " data-rpst-movie-no=\"" + (index + 1) + "\"><i title=\"보고싶어 설정 안함\" class=\"iconset ico-heart-toggle-gray\"></i>" + "" 
				+ likes + "" + "</button><div class=\"case\"><a href=\"../booking/cineReserve;\" class=\"button gblue\" title=\"영화 예매하기\">예매</a></div></div></li>";

			$(".my-reserve-history").append(htmlToInsert);
			});
		}
	});
}



	
	