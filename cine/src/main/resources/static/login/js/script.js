
        function openModal() {
            document.getElementById('myModal').style.display = 'block';
            showTab('loginTab');
        }

        function closeModal() {
            document.getElementById('myModal').style.display = 'none';
        }

        function showTab(tabName) {
            var i;
            var tabs = document.getElementsByClassName('tab');
            for (i = 0; i < tabs.length; i++) {
                tabs[i].style.display = 'none';
            }

            var tabContent = document.getElementById(tabName);
            tabContent.style.display = 'block';

            if (tabName === 'loginTab') {
                // /login 페이지의 내용을 가져오기 위한 XMLHttpRequest 요청
                var xhr = new XMLHttpRequest();
                xhr.open('GET', '/login', true);
                xhr.onreadystatechange = function() {
                    if (xhr.readyState === 4 && xhr.status === 200) {
                        // 가져온 내용을 로그인 탭에 채워 넣습니다.
                        tabContent.innerHTML = xhr.responseText;
                    }
                };
                xhr.send();
            }
        }
 