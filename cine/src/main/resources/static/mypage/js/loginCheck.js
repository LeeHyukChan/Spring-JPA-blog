$(document).ready(function() {

	$.ajax({
		type: "GET",
		url: "/userinfo",
		dataType: 'json',

		success: function(data) {

			$('#reserve').on('click', function(e) {

				console.log('예매 클릭')
				console.log(data)
				/*console.log(data.entiMemId)*/

				if (data === null || data === undefined) {
					// 'loginid' 값이 null이거나 undefined인 경우
					e.preventDefault();
					console.log('로그인되지 않음');
					openModal();

				} else{
					console.log('로그인');
				}


			});



		},
		error: function() {

			console.log("에러: ");
		}
	});


});







