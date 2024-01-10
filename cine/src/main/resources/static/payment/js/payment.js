

// 세션에서 가져와 결제에 표시


// 영화 포스터 
document.addEventListener("DOMContentLoaded", function() {
	
	var imglink = sessionStorage.getItem("imglink")
	console.log(imglink)
	
	var image = document.getElementById("imglink"); // "yourImageId"는 이미지 태그의 ID입니다.
	
	
	// 이미지의 src 속성을 변경합니다.
	image.src = imglink;
});


// 영화 타이틀 
document.addEventListener("DOMContentLoaded", function() {


	// 
	var sessionMovname = sessionStorage.getItem("movieName");
	console.log(sessionMovname)


	document.querySelector(".movieName").textContent = "영화 : " + sessionMovname
	
	
	console.log(document.querySelector(".movieName").textContent)

});


// 극장 지역1
document.addEventListener("DOMContentLoaded", function() {

	var sessionMovArea = sessionStorage.getItem("movieArea");
	console.log(sessionMovArea)


	document.querySelector(".movieArea").textContent = "지역 : " +  sessionMovArea
	
	
	console.log(document.querySelector(".movieArea").textContent)

});


// 극장 지역2
document.addEventListener("DOMContentLoaded", function() {

	var sessionMovArea2 = sessionStorage.getItem("movieArea2");
	console.log(sessionMovArea2)


	document.querySelector(".movieArea2").textContent =  "상영관 : " + sessionMovArea2
	
	
	console.log(document.querySelector(".movieArea2").textContent)

});



// 날짜 
document.addEventListener("DOMContentLoaded", function() {

	var sessionDate = sessionStorage.getItem("movieDate");
	console.log(sessionDate)
 	document.querySelector(".movieDate").textContent =  "일시 : " + sessionDate
	
	
	
	var seesionTime = sessionStorage.getItem("movieTime");
	console.log(seesionTime)
	document.querySelector(".movieTime").textContent =  "시간 : " + seesionTime
	

});

// 인원
document.addEventListener("DOMContentLoaded", function() {

	var sessionPerson = sessionStorage.getItem("totalCount");
	console.log(sessionPerson)
	document.querySelector(".moviePerson").textContent =  "인원 : " + sessionPerson
	

});

// 좌석  
document.addEventListener("DOMContentLoaded", function() {

	var sessionSeats = sessionStorage.getItem("seats")
	
	var sessionObject = JSON.parse(sessionSeats)
	console.log(sessionObject)
	document.querySelector(".movieSeats").textContent =  "좌석 : " + sessionObject
	

});

// 요금 
document.addEventListener("DOMContentLoaded", function() {

	var sessionMoney = sessionStorage.getItem("money")
	
	console.log(sessionMoney)
	document.querySelector(".moviePrice").textContent =  "가격 : " + sessionMoney
	

});



$(document).on('click', '#paynow', function() {
		const queryString = window.location.search;
		const urlParams = new URLSearchParams(queryString);
		
		const numValues = urlParams.get("numValues");
		const movieName = urlParams.get("movieName");
		
		console.log(numValues); 
		console.log(movieName); 

		var bookingURL = "/update?numValues=" + numValues + "&movieName=" + movieName;
		
		console.log(bookingURL);
		window.location.href = bookingURL;
		
	

});




















