
$(document).ready(function() {

   $.ajax({
      type: "GET",
      url: "/movies",
      dataType: 'json',

      success: function(data) {
        console.log("mypage CONSOLE");
         list(data)
      },
      error: function() {

         console.log("####################에러: ");
      }
   });
});



function list(data,likecount) {
    $(".main-movie-list .list").empty();
    //console.log("&nbsp&nbsp&nbsp="+data );
    $.each(data, function(index, item) {
        if (index < 4) {
            if (index === 0) {
                var rank = "first"
            }
            var htmlToInsert = "<li name=\"li_boxoRankList\" class=\"" + rank + "\"><a href=\"javascript:gfn_moveDetail('23066600')\" class=\"movie-list-info\" title=\"영화상세 보기\"><p class=\"rank\">" +
                (index + 1) + "<span class=\"ir\">위</span></p><img src=" + item.imglink + " alt=\"" + item.title + "\" class=\"poster\" onerror=\"noImg(this, 'main');\"><div class=\"wrap\" style=\"display: none; opacity: 1;\"><div class=\"summary\"><br>" + item.moviecontent + "</div><div class=\"score\"><div class=\"preview\"><p class=\"tit\">관람평</p><p class=\"number\">9.3<span class=\"ir\">점</span></p></div></div></div></a><div class=\"btn-util\"><button type=\"button\" class=\"button btn-like\""+ likecount + " data-rpst-movie-no=\"" + index + "\"><i title=\"보고싶어 설정 안함\" class=\"iconset ico-heart-toggle-gray\"></i>" + "likecount" + "</button><div class=\"case\"><a href=\"javascript:moveBokdPage('23066600');\" class=\"button gblue\" title=\"영화 예매하기\">예매</a></div></div></li>";

            $(".main-movie-list .list").append(htmlToInsert);
        }
    });
}
$(document).on("mouseenter", ".list li", function() {
    $(this).find(".wrap").css("display", "block");
}).on("mouseleave", ".list li", function() {
    $(this).find(".wrap").css("display", "none");
});