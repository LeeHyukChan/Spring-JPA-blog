// 현재 날짜를 생성


$(document).ready(function() {
   // date-area 클래스를 가진 요소를 찾아서 empty() 메서드 적용
   var today = new Date();
   today.setDate(today.getDate() - 1)
   $("#formDeList .wrap").empty();
   // 13일 후의 날짜를 계산하고 출력
   for (var i = 0; i < 15; i++) { // 0부터 13까지 총 14일
      var options = { year: 'numeric', month: 'numeric', day: 'numeric' };
      var formattedDate = today.toLocaleDateString(undefined, options);

      //클래스 속성
      var dayClass = "on";
      // 년도, 월, 일, 그리고 요일을 얻기
      var year = today.getFullYear();
      var month = today.getMonth() + 1; // 월은 0부터 시작하므로 1을 더함
      var day = today.getDate();
      var dayOfWeek = today.toLocaleDateString(undefined, { weekday: 'long' });

      /*console.log("오늘: " + formattedDate + " (" + dayOfWeek + ")");
      console.log("년도: " + year);
      console.log("월: " + month);
      console.log("일: " + day);
      console.log("무슨요일: " + dayOfWeek);
      console.log(dayOfWeek[0]);*/
      if(dayOfWeek[0]==="토"){
         dayClass='sat';
      }
      else if(dayOfWeek[0]==="일"){
         dayClass='holi';
      }
      else {
         dayClass=" ";
      }
      if (i===1){
		 dayClass=dayClass+" on" 
	  }
      // 버튼 요소를 생성하고 속성을 설정
      var buttonHtml = '<button class='+dayClass+' type="button" date-data='+[year, month, day].join(".")+' month="9">' +
         '<span class="ir">'+year+'년 '+month+'월</span>' +
         '<em style="pointer-events:none;">'+day+'<span style="pointer-events:none;" class="ir">'+dayOfWeek[0]+'</span></em>' +
         '<span class="day-kr" style="pointer-events:none;display:inline-block">'+dayOfWeek[0]+'</span>' +
         '<span class="day-en" style="pointer-events:none;display:none">'+dayOfWeek[0]+'</span>' +
         '</button>'
      
      // 버튼 요소를 #formDeList에 추가
      $("#formDeList .wrap").append(buttonHtml);
      
      // 다음 날짜로 이동
      today.setDate(today.getDate() + 1);
   }
});s