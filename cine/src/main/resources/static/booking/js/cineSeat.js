// 현재 URL에서 쿼리 문자열을 가져옵니다.
var queryString = window.location.search;

// URLSearchParams 객체를 생성하여 쿼리 문자열을 파싱합니다.
var searchParams = new URLSearchParams(queryString);

// URLSearchParams 객체를 사용하여 데이터를 추출합니다.
var playStartTime = searchParams.get("playStartTime");
var movieName = searchParams.get("movieName");
var theaterNumber = searchParams.get("theaterNumber");
var theaterName = searchParams.get("theaterName");
var imglink = searchParams.get("imglink");





//seat 불러오기
$(document).ready(function() {
    setTimeout(function() {
        loadSeat();
    }, 1000); // 1000 밀리초(1초) 후에 loadSeat 함수 실행
});
function loadSeat() {
	$.ajax({
		type: "GET",
		url: '/seats', // 실제 서버 엔드포인트로 대체
		dataType: 'json',

		success: function(data) {
			// JSON 데이터를 HTML에 표시
			seat(data);
		},
		error: function() {
			alert('seat JSON 파일을 불러오는 중 오류가 발생했습니다.');
		}

	});
}
function seat(data) {
	// JSON 데이터를 HTML에 표시
	//$(".row").empty();
	$.each(data, function(index, item) {
		//console.log(movieName);
		//console.log(item.movietitle);
		if(movieName ==  item.movietitle && item.starttime == playStartTime && item.theaterName == theaterName)
		{
		/*console.log(item.seatrow);*/
		/*console.log(item.seatcol);*/
		var $rowElement = $(".row button[seatno='" + item.seatcol + "'][rownm='" + item.seatrow.toUpperCase() + "']");
		$rowElement.removeClass();
		
		var set = "jq-tooltip seat-condition standard ";
		$rowElement.addClass(set + item.seatstate);
		$rowElement.attr("id", item.id);

		}
	})
}






// + 버튼을 클릭할 때
var totalCount = 0;
var adultCount = 0;
var childCount = 0;
var disCount = 0;

// 세션 저장 변수들 
var sessiontotalCount = 0;
var seats = new Set();


//인원수 증가
$(document).on("click", ".count .up", function(event) {
	if ($(".row button.choice").length > 0) {
		event.preventDefault(); // 클릭 이벤트를 중지
		alert("좌석을 선택 한 후 인원 수를 수정할 수 없습니다.");

	}
	else {
		count = parseInt($(this).parent().find(".now").text(), 10);
		$(this).parent().find(".now").text(++count);
		childCount = parseInt($(".child").text(), 10);  // 현재 클릭된 버튼의 형제 요소 중 클래스가 'child'인 요소의 텍스트를 가져와 정수로 변환합니다.
		adultCount = parseInt($(".adult").text(), 10);
		disCount = parseInt($(".dis").text(), 10);
		totalCount = adultCount + disCount + childCount;
		
		// 세션에 인원 수 저장
		sessionStorage.setItem("totalCount",totalCount)
		sessiontotalCount= sessionStorage.getItem("totalCount")
		console.log(sessiontotalCount)
	}
})
//인원수 감수 
$(document).on("click", ".count .down", function(event) {
	count = parseInt($(this).parent().find(".now").text(), 10);

	if ($(".row button.choice").length > 0) {
		event.preventDefault(); // 클릭 이벤트를 중지
		alert("좌석을 선택 한 후 인원 수를 수정할 수 없습니다.");

	}
	else {
		if (count > 0) {
			$(this).parent().find(".now").text(--count);
		}
		childCount = parseInt($(".child").text(), 10);  // 현재 클릭된 버튼의 형제 요소 중 클래스가 'child'인 요소의 텍스트를 가져와 정수로 변환합니다.
		adultCount = parseInt($(".adult").text(), 10);
		disCount = parseInt($(".dis").text(), 10);
		totalCount = adultCount + disCount + childCount;
		
		//세션에 인원 수 저장 
		sessionStorage.setItem("totalCount",totalCount)
		sessiontotalCount= sessionStorage.getItem("totalCount")
		console.log(sessiontotalCount)
	}
})


//좌석 증감
$(document).on("click", ".jq-tooltip", function(event) {
	if (!$(this).hasClass("choice") && !$(this).hasClass("FINISH")) {
		if (totalCount > 0) {
			if ($(this).hasClass("DISABLED")) {
				alert("장애인이 아닐 시 예매가 취소될 수 있습니다.");
				$(this).addClass('choice');
				totalCount--;
				$(".my-seat > .seat:not(.choice):first").addClass("choice").text($(this).attr("rownm") + $(this).attr("seatno"));
				
				// 좌석 리스트 추가 
				$(".my-seat .seat.choice").each(function() {
				    const seatValue = $(this).text();
		    		console.log("추가한" + seatValue)
				    seats.add(seatValue)
				    console.log(seats);
				});

				
			}
			else if ($(this).hasClass("finish")) {
				alert("이 자리는 선택할 수 없습니다.");
			}
			else {
				$(this).addClass('choice');
				totalCount--;
				$(".my-seat > .seat:not(.choice):first").addClass("choice").text($(this).attr("rownm") + $(this).attr("seatno"));
				
				
				// 좌석 리스트 추가 
				$(".my-seat .seat.choice").each(function() {
				    const seatValue = $(this).text();
		    		console.log("추가한" + seatValue)
				    seats.add(seatValue)
				    console.log(seats);
				});
			}
			

			
		}
		else {
			event.preventDefault();
			alert("더 이상 좌석을 추가할 수 없습니다.");
		}
	}
	else if ($(this).hasClass("FINISH")) {
		alert("이미 선택된 좌석입니다.");
	}

	else if ($(this).hasClass("choice")) {
		$(this).removeClass('choice');
		totalCount++;
		
		
		// 좌석 리스트 삭제 
		$(".my-seat > .seat.choice:last").each(function() {
		    const seatValue = $(this).text();
		    
		    console.log("삭제한" + seatValue)
		    
		    seats.delete(seatValue)
		    console.log(seats);
		});
		
		
		$(".my-seat > .seat.choice:last").removeClass("choice").empty().text('-');
		
			
		

	}

	$(".money em").empty().text((Number("15000") * $(".my-seat > .seat.choice").length).toLocaleString());

	$(".money em").each(function() {
	    const movMoney = $(this).text();
	    
	    console.log("요금 변화 : " + movMoney)
	    sessionStorage.setItem("money",movMoney)
	    
	});



	var hasChoice = $(".my-seat > .seat.choice").length > 0;
	$("#pageNext").removeClass(hasChoice ? "disabled" : "active").addClass(hasChoice ? "active" : "disabled");
	
	
	// set을 json 형태로 파싱 
	const seatsJSON = JSON.stringify([...seats]);
	// 세션에 set객체 저장
	sessionStorage.setItem("seats", seatsJSON)
	
	const sessionData =  sessionStorage.getItem("seats")
	const sessionObject = JSON.parse(sessionData)
	
	console.log(sessionObject)
});







//초기화
$(document).on("click", "#seatMemberCntInit", function(event) {

	event.preventDefault();
	loadSeat();
	$('.number').children('button').text('0');
	totalCount = 0;
	$(".my-seat div").removeClass("choice").empty().text('-');
	$(".money em").text('0');
	$(".money em").each(function() {
	    const movMoney = $(this).text();
	    
	    console.log("요금 변화 : " + movMoney)
	    sessionStorage.setItem("money",movMoney)
	    
	});


});





$(document).on('click', '#pageNext', function() {
	
	
	sessionStorage.setItem('imglink', imglink);
	console.log(imglink)
	
	if ($(this).hasClass("active")) {
		var numValues = [];
		$(".choice").each(function() {
			if ($(this).attr('id')) {
				numValues.push($(this).attr('id'));
				

			}
		})

		console.log(sessiontotalCount)

		// var bookingURL = "/update?numValues=" + numValues.join(",") + "&movieName=" + movieName;
		var bookingURL = "/payment?numValues=" + numValues.join(",") + "&movieName=" + movieName;
		console.log(bookingURL);
		//parent.location.href = bookingURL;
		window.location.href = bookingURL;
	}

});

