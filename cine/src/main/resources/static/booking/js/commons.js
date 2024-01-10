$.getScript('/static/mb/js/lozad.min.js');

$(function(){

    $.datepicker.regional[ "ko" ] = {
            closeText: "닫기",
            prevText: "이전달",
            nextText: "다음달",
            currentText: "오늘",
            monthNames: ["1월","2월","3월","4월","5월","6월","7월","8월","9월","10월","11월","12월"],
            monthNamesShort: ["1월","2월","3월","4월","5월","6월","7월","8월","9월","10월","11월","12월"],
            dayNames: ["일","월","화","수","목","금","토"],
            dayNamesShort: ["일","월","화","수","목","금","토"],
            dayNamesMin: ["일","월","화","수","목","금","토"],
            weekHeader: "Wk",
            dateFormat: Constants.DATE_FORMAT_CAL,
            firstDay: 0,
            isRTL: false,
            duration:200,
            showAnim:"show",
            showMonthAfterYear: true,
            yearSuffix:"년",
            showOtherMonths : true ,
            selectOtherMonths : true
    };
    $.datepicker.setDefaults( $.datepicker.regional["ko"] );

    // 웹에서만 실행 -> facebook을 로드하지 않는 템플릿에서 반복적인 오류 발생으로 hreader로 이전
    //if(!MegaboxUtil.Common.isMobile() && !MegaboxUtil.Common.isApp())
    //    MegaboxUtil.Share.init();
});

$.fn.megaBoxNumberCheck = function() {

    $(this).on("keypress",function(e){
        if ( !e.key.isNumber() ) return false;
    });
    $(this).on("keyup",function(e){
    	// input 에서 클릭 후 자동완성 값을 선택하는 경우에는 e.key 값은 undefined 임에 유의
        if (e.key && !e.key.isNumber() ){
            var inputVal = $(this).val();
            $(this).val(inputVal.replace(/[^0-9]/gi,''));
        }
    });
    $(this).on("focusout",function(e){
        $(this).val($(this).val().replace(/[^0-9]+/g, ''));
    });
};

$.fn.passTrim = function() {

	    $(this).on("keypress",function(e){
	        if ( e.key.indexOf(' ') > -1 ) return false;
	    });
	    $(this).on("keyup",function(e){
	    	var inputVal = $(this).val();
            $(this).val(inputVal.replace(/(^\s*)|(\s*$)/gi,''));
	    });
	    $(this).on("focusout",function(e){
	        $(this).val($(this).val().replace(/(^\s*)|(\s*$)/gi, ''));
	    });
	};

$.fn.megaBoxNumberHPCheck = function() {

    $(this).on("keypress",function(e){
        if ( !e.key.isNumber() ) return false;
    });
    $(this).on("keyup",function(e){
        if ( !e.key.isNumber() ){
            var inputVal = $(this).val();
            $(this).val(inputVal.replace(/[^0-9]/gi,''));
        }
    });
    $(this).on("focusout",function(e){
        $(this).val($(this).val().replace(/\B(?=(\d{4})+(?!\d))/g, '-'));
    });
    $(this).on("focusin",function(e){
        $(this).val($(this).val().replace(/[-]/g, ''));
    });
};

/**
 * 유효하지 않은 비밀번호 문자를 공백으로 치환한다.
 * @author AJ
 * @date 2020.04.15 최초 생성
 * @date 2020.06.26 비밀번호 인풋 툴팁 액션 컨트롤 기능 추가
 */
$.fn.megaBoxPwdCheck = function() {
    var regEx = /[^0-9a-zA-Z~!@#$%^&*+=\-?_]/gi;

    if(new RegExp(regEx).test($(this).val())) {
        $(this).val($(this).val().replace(regEx, ''));

        if ($(this).hasClass('unclickable')) {
            return;
        }

        $(this).addClass('unclickable');

        // 모바일에서 jQuery tooltip 으로 구현된 경우
        if ($(this).data('ui-tooltip')) {
            $(this).tooltip('open');
            setTimeout(function() {
                $(this).tooltip('close');
                $(this).removeClass('unclickable');
            }.bind(this), 1000);
        }

        // PC에서 CSS로 툴팁이 구현된 경우
        if ($(this).next('.tooltiptext').length) {
            $(this).next('.tooltiptext').fadeIn(function () {
                setTimeout(function () {
                    $(this).next('.tooltiptext').fadeOut();
                    $(this).removeClass('unclickable');
                }.bind(this), 1000);
            }.bind(this));
        }
    }
};

var clickLmtAt = true;	//클릭 허용여부
var clickLmtUrl;		//호출 URL

function clearLmt(){
    clickLmtAt = true
}

$.ajaxMegaBox = function ( options ) {
    var setting = $.extend({
        url           : ""
       ,type          : "POST"
       ,method        : "POST"
       ,contentType   : "application/json; charset=UTF-8"
       ,dataType      : "json"
       ,secure        :"N"
       ,data          : {}
       ,processData   : true
       ,async         : true
       ,cache         : true
       ,global        : true
       ,jsonp         : null
       ,jsonpCallback : null
       ,complete      : null
       ,success       : null
       ,error         : null
       ,errorMsgYn    : true
       ,sessionAt     : false
       ,commAt        : false
       ,clickLmtChk   : false
    },options);

    //중복 클릭 방지
    if( setting.clickLmtChk ){
        //중복여부 및 동일URL호출 여부를 체크하여 실행방지
        if( clickLmtAt || clickLmtUrl != setting.url ){
            clickLmtAt = false;
            clickLmtUrl = setting.url;
            setTimeout(clearLmt, 3 * 1000);
        }else{
            gfn_alertMsgBox('중복 클릭 방지');
            return;
        }
    }

    var domin = "";
    if( setting.url == "" ) {
        if( setting.secure == "Y" ) {
            if( location.hostname.indexOf('localhost') > -1 ) {
                domin="https://"+location.hostname + ":443";
            } else {
                domin="https://"+location.hostname;
            }
        } else {
            if( location.hostname.indexOf('localhost') > -1 ) {
                domin="http://"+location.host;
            } else {
                domin="http://"+location.hostname;
            }
        }
    }
    setting.url = domin + setting.url;

    if( !sessionAllow( setting ) ) return

    $.ajax($.extend(setting,{
        error         : function(xhr,status,error){
            try {
                if ( setting.errorMsgYn ) {
                    // responseJSON
                       var err = JSON.parse(xhr.responseText);
                       var options = {};
                       options.msg      = err.msg;
                       options.param    =  {xhr:xhr,status:status,error:error,setting:setting};

                       if(MegaboxUtil.Common.isMobile()) AppHandler.Common.alert(gfn_scrtDecode(err.msg));
                       else gfn_alertMsgBox(options);
                } else {
                       if ( setting.error ) {
                           setting.error(xhr,status,error);
                       }
                }
            } catch (e) {
                console.log("ajaxMegaBox Exception");
            }

            //에러발생시 모달창 닫기
            if( $("#bg-loading").length > 0 ){
                gfn_logdingModal();
            }
        }
    }));
}

/**
 * 제이쿼리 더블탭 이벤트
 * 사용법: $(selector).on('doubleTap', callback);
 *
 * @author AJ
 */
$.event.special.doubleTap = {
    bindType: 'touchend',
    delegateType: 'touchend',

    handle: function(event) {
        var handleObj   = event.handleObj,
            targetData  = jQuery.data(event.target),
            now         = new Date().getTime(),
            delta       = targetData.lastTouch ? now - targetData.lastTouch : 0,
            delay       = delay == null ? 300 : delay;

        if (delta < delay && delta > 30) {
            targetData.lastTouch = null;
            event.type = handleObj.origType;
            ['clientX', 'clientY', 'pageX', 'pageY'].forEach(function(property) {
                event[property] = event.originalEvent.changedTouches[0][property];
            });

            // let jQuery handle the triggering of "doubletap" event handlers
            handleObj.handler.apply(this, arguments);
        } else {
            targetData.lastTouch = now;
        }
    }
};

/**
 * 옵션값과 나의메가박스일 경우 세션체크
 * @param setting
 * @returns
 */
function sessionAllow( setting ){

    var sessionMsg = "";

    //공통여부 체크
    if( setting.commAt ) return true;

    //로그인 관련 호출
    if( setting.url != undefined && setting.url.indexOf("/MbLogin") > -1 ) return true;

    //세션여부 체크
    if( setting.sessionAt || location.pathname.indexOf("/mypage") == 0 || location.pathname.indexOf("/myMegabox") == 0 ){
        $.ajax({
            url        : '/sessionChk.do',
            type       : 'POST',
            contentType: 'application/json;charset=UTF-8',
            dataType   : 'json',
            async      : false,
            success    : function (data, textStatus, jqXHR) {

                if( data.loginYn == "Y" ){

                }else{
                    //sessionMsg = "로그인 후 이용가능한 서비스입니다. <br/>(에러-common)";
                    sessionMsg = "로그인 후 이용가능한 서비스입니다.";
                }

            },
            error      : function(xhr,status,error){
                //sessionMsg = "잘못된 접근입니다. <br/>(에러-common)";
                sessionMsg = "잘못된 접근입니다.";
            }
        });
    }

    if( sessionMsg != "" ){
        var callback = undefined;
        if (!isApp()) {
            callback = function () {
                //fn_viewLoginPopup('default','pc');
                //마이페이지 메인으로 이동
                if (location.pathname.indexOf("/mypage") == 0 || location.pathname.indexOf("/myMegabox") == 0) {
                    if (sysCd == "MON") {
                        AppHandler.Common.goMain();
                    } else {
                        location.href = "/";
                    }
                }
            }
        }
        gfn_alertMsgBox(sessionMsg, callback);
        return false;
    }
    return true;

    function isApp() {
        var filterData = 'MegaBox';
        return navigator.userAgent.indexOf(filterData) > -1;
    };
}

// 공통 스크립트
var Common = function() {
    var reloadType = false;

    /**
     * 페이지 내 셀렉트 박스 라이브러리 적용
     */
    this.bindSelectBox = function(options) {

        var setting = $.extend({
            obj    : $('select')
          , size   : 10
        }, options);

        setting.obj.selectpicker({
            dropdownAlignRight: 'auto',
            dropupAuto: true,
            size: setting.size // 옵션값 출력 최대 갯수 . 숫자 이상은 스크롤 처리 됨
        });
    }

    /**
     * 라이브러리 적용된 셀렉트 박스 초기화
     * @param target : 셀렉트 박스 제이쿼리 객체
     */
    this.refreshSelectBox = function(target) {
        target.selectpicker('refresh');
    };

    /**
     * 문자열 길이 체크
     * @param str : 문자
     * @retruns int : 문자열 길이 값
     */
    this.strByteLength = function(str) {
        var totalByte = 0;
        var strLen = str.length;
        var charData;
        if(strLen == 0) return 0;
        for(var i = 0; i < strLen; ++i) {
            charData = str.charAt(i);

            if(escape(charData).length > 4) {
                totalByte += 2;
            } else {
                totalByte++;
            }
        }
        return totalByte;
    };

    /**
     * 문자열 길이 체크
     * @param str : 문자
     * @retruns int : 문자열 길이 값
     */
    this.strByteLengthGetLen = function(str, maxByte) {
        var strLen = str.length;
        var charData;
        var result = {
                length : 0
                , totalByte : 0
        };
        if(strLen == 0) return result;
        for(var i = 0; i < strLen; ++i) {
            charData = str.charAt(i);
            result.length = i;

            if(escape(charData).length > 4) {
                result.totalByte += 2;
            } else {
                result.totalByte++;
            }

            if( result.totalByte > maxByte ){
                break;
            }
        }

        return result;
    };

    /**
     * 모바일 디바이스 체크
     * @returns Boolean : true(모바일), false(웹)
     */
    this.isMobile = function() {
        var result = false;
        var filterData = ['iPad', 'iPhone', 'Android'];

        $.each(filterData, function(i, v) {
            if(navigator.userAgent.indexOf(v) > -1) {
                return result = true;
            }
        });

        return result;
    };

    /**
     * 모바일 앱 체크
     * @returns Boolean - 앱:true, 웹:false
     */
    this.isApp = function() {
        var result = false;
        var filterData = 'MegaBox';

        if (navigator.userAgent.indexOf(filterData) > -1) {
            return result = true;
        }

        return result;
    }

    /**
     * 디바이스에 따른 얼럿창
     * @param data : 메세지 정보
     * @param reloadTy : 페이지 리로드 여부
     */
    this.alert = function(data, reloadTy) {
        if(MegaboxUtil.Common.isMobile()) {
            // Object 일 경우,
            // 모바일 App, Web은 MegaboxUtil.Common.alert()을 사용하지 않고
            // AppHander.Common.alert() 함수로 별도 처리한다.
            if(data instanceof Object) {
                if(data.confirmFn && data.param.confirm) {
                    if(confirm(data.msg)) {
                        data.confirmFn(data.param.confirm);
                    } else {
                        data.confirmFn(data.param.cancelFn);

                        // 2019.04.17 - 모바일개발 채운기
                        // 이게 맞는거죠?
                        /*
                        if(data.cnacelFn && data.param.cancel) {
                            data.cancelFn(data.param.cancel);
                        }
                        */
                    }
                } else if(data.callback && data.param.confirm) {
                    if(data.msg) {
                        alert(data.msg);
                    }

                    data.callback(data.param.confirm);
                }
            } else {
                // 모바일 App 일 때
                if (MegaboxUtil.Common.isApp()) {
                    AppHandler.Common.alert(data);
                }
                // 모바일 Web 일 때
                else {
                    alert(data);
                }
            }
        } else {
            reloadType = reloadTy;

            gfn_alertMsgBox(data, MegaboxUtil.Common.alerCallback);
        }
    };

    /**
     * 레이어 얼럿창 확인 후 리턴 함수
     */
    this.alerCallback = function() {
        if(reloadType) {
            location.reload();
        }
    };

    /**
     * 숫자만 입력 가능한 인풋 설정
     */
    this.bindNumberTypeEvent = function() {
        $('.numType').on('keyup', function() {
            var bfVal = this.bfVal;

            if(isNaN(this.value)) {
                $(this).val('');
            }
        }).on('keydown', function() {
            this.bfVal = this.value;
        });
    };
    /**
     * 텍스트아레아 포커스
     * @param id : 텍스트 아레아 아이디 없을시 textarea 자동 설정
     */
    this.bindTextateaLengthEvent = function(options) {
        var setting = $.extend({
            objId  : 'textarea',
            cntId  : 'textareaCnt',
            obj    : '',
            cnt    : '',
            maxLen : 2000
        }, options);

        if (setting.obj == '') {
            setting.obj = $('#'+ setting.objId);
        }
        if (setting.cnt == '') {
            setting.cnt = $('#'+ setting.cntId);
        }

        setting.obj.on('change input', function() {
            var result = MegaboxUtil.Common.strByteLengthGetLen(this.value, setting.maxLen);
            if (result.totalByte > setting.maxLen) {
                MegaboxUtil.Common.alert('최대 '+ setting.maxLen + 'byte까지 입력 가능합니다.');
                this.value = this.value.substring(0, result.length);
                setting.cnt.text(MegaboxUtil.Common.strByteLength(this.value));
            } else {
                setting.cnt.text(result.totalByte);
            }
        });
    };
    /**
     * 텍스트아레아 포커스
     * @param id : 텍스트 아레아 아이디 없을시 textarea 자동 설정
     */
    this.bindTextateaLengthEventSubStr = function(id, options) {

        var targetId = id ? '#' + id : '#textarea';
        var setting = $.extend({
             maxLen     : 2000
         },options);

        $(targetId).bind("change keyup input", function(e) {
            var result = MegaboxUtil.Common.strByteLengthGetLen(this.value, setting.maxLen);
            console.log("result : "+result.length + " : "+$(this).val() + " : "+$(this).val().substr(result.length));

            if( result.totalByte > setting.maxLen ){
                MegaboxUtil.Common.alert('최대 '+ setting.maxLen + 'byte까지 입력 가능합니다.');
                $(this).val($(this).val().substr(0, result.length));
                $('#textareaCnt').text(setting.maxLen);
            }else{
                $('#textareaCnt').text(result.totalByte);
            }
        });
    };

    /**
     * Ajax 데이터 전송
     */
    this.selectList = function(obj) {
        $.ajaxMegaBox({
            type       : "POST",
             contentType: "application/json;charset=UTF-8",
             url        : obj.url,
             dataType   : "json",
             data       : JSON.stringify(obj.data),
             async      : true,
             success: obj.success,
               error: obj.error ? obj.error : error
        });
    };

    /**
     * Ajax 에러시 디폴트 함수
     */
    var error = function (jqXHR, textStatus, errorThrown) {
        MegaboxUtil.Common.alert("오류가 발생하였습니다.");
    };

    /**
     * 목록 다음 페이지 존재 여부 체크
     * @params currentPage: 현재 페이지번호, recordCountPerPage: 최대 페이징 수, totalCnt: 총 목록 수
     * @returns
     */
    this.isPaging = function(currentPage, recordCountPerPage, totalCnt) {
        var totalPage = Math.ceil(totalCnt / recordCountPerPage);

        if(totalPage > currentPage) return true;
        else return false;
    };

    /**
     * 영화제 존재 여부 체크(GNB용)
     */
    this.moveMovieFilmCheckGnb = function() {
        var filmCheck = true;
        $.ajaxMegaBox({
             url: '/on/oh/oha/Movie/selectFilmfsvList.do',
             async : false,
             success: function(d) {
                 if(d.list.length > 0) { // 영화제 존재시
                     filmCheck = true;
                 } else {                // 영화제 미존재시
                     filmCheck = false;
                 }
             }
        });
        return filmCheck;
    };


    /**
     * 영화제 존재 여부 체크(Sitemap용)
     */
    this.moveMovieFilmCheck = function() {
        $.ajaxMegaBox({
            url: '/on/oh/oha/Movie/selectFilmfsvList.do',
            success: function(d) {
                if(d.list.length > 0) { // 영화제 존재시
                    location.href = '/festival';
                } else { // 영화제 미존재시
                    MegaboxUtil.Common.alert('현재 진행중인 영화제가 없습니다.');
                }
            }
        });
    };
};

// 폼 체크
var Form = function() {
    var formData;
    var idPattern = /^(?=.*[0-9])[a-zA-Z0-9]{8,12}$/gi;
    var pwPattern= /((?=.{10,})(?=.*[0-9])(?=.*[a-zA-Z])(?!.*[^0-9a-zA-Z~!@#$%^&*+=\-_?]).*$)|((?=.{10,})(?=.*[~!@#$%^&*+=\-_?])(?=.*[a-zA-Z])(?!.*[^0-9a-zA-Z~!@#$%^&*+=\-_?]).*$)|((?=.{10,})(?=.*[!@#$%^&*+=\-_?])(?=.*[0-9])(?!.*[^0-9a-zA-Z~!@#$%^&*+=\-_?]).*$)/gi;
    var emailPattern= /((?=.{3,})(?=.*[@])(?=.*[\.]).*$)/gi;

    var pattern = {
        id: idPattern,
        pw: pwPattern,
        email: emailPattern
    };

    /**
     * 페이지 이동을 위한 폼 생성
     * @returns 제이쿼리 폼
     */
    this.createForm = function() {
        var form = $('<form>').attr({ name: 'movieForm', method: 'post' });

        /**
         * HTML5 표준에선 Browsing contexts(document) 에 form 이 연결되어 있지 않으면, form submit을 중단하도록 규정
         * 동적 생성시 	body에 append
         */
        //$('footer').append(form);
        $('body').append(form);

        return form;
    };

    /**
     * 폼 가져오기
     * @param name : 폼 네임
     * @returns 제이쿼리 폼
     */
    this.getForm = function(name) {
        return $(document.forms[name]);
    };

    /**
     * Ajax 등록 처리
     * @param form : 제이쿼리 폼
     * @param obj : Ajax 옵션
     */
    this.send = function(form, obj) {
        formData = obj;

        if(obj.headers == undefined){
            obj.headers = null;
        }

        $.ajaxMegaBox({
             url         : obj.url,
             data        : JSON.stringify(obj.data),
             clickLmtChk : obj.clickLmtChk ? obj.clickLmtChk : false,
             headers     : obj.headers ? obj.headers : null,
             success     : obj.success ? obj.success : fn_success,
             error       : obj.error ? obj.error : fn_error,
             complete    : obj.complete ? obj.complete : clearLmt
        });
    };

    /**
     * Ajax 성공시 기본 함수
     */
    var fn_success = function(result){
        MegaboxUtil.Common.alert(formData.sMsg ? formData.sMsg : "저장 되었습니다.", true);
      };
      /**
       * Ajax 실패시 기본 함수
       */
      var fn_error = function () {
          MegaboxUtil.Common.alert(formData.eMsg ? formData.eMsg : "오류가 발생하였습니다.");
      };
      /**
       * 폼 데이터 오브젝트로 변환
       * @param form : 제이쿼리 폼
       * @returns Object
       */
      this.getFormObjData = function(form) {
        var arr = form.serializeArray();
        var obj = {};

        $.each(arr, function(i, v) {
            obj[v.name] = v.value;

            if(v.name == 'lentDe') {
                obj[v.name] = v.value.replace(/[-,.]/gi, '');
            }
        });
        return obj;
    };
    /**
     * 폼 인풋 데이터 빈값이 있는지 체크
     * @param form : 제이쿼리 폼
     * @retuens Boolean : true(빈값 존재), false(빈값 없음)
     */
    this.checkInputNonData = function(form) {
        var result = false;
        var obj = MegaboxUtil.Form.getFormObjData(form);

        $.map(obj, function(value, key) {
            input = form.find('[name=' + key + ']');

            if(form.find('[name=' + key + ']').val() == '') {
                return result = true;
            }
        });

        return result;
    };
    /**
     * 폼 input 생성
     * @param dataForm : 데이터를 가져올 제이쿼리 폼
     * @param targetForm : 인풋을 생성할 제이쿼리 폼
     */
    this.createInput = function(dataForm, targetForm) {
        var obj = MegaboxUtil.Form.getFormObjData(dataForm);
        var input, checkType, val;

        $.map(obj, function(value, key) {
            input = targetForm.find('[name=' + key + ']');
            checkType = dataForm.find(getInputCheckType(dataForm, key));
            val = checkType && value == '' ? 'N' : value;

            if(input.length == 0) {
                input = $('<input>').attr({ type: 'hidden', name: key }).val(val);

                targetForm.append(input);
            } else {
                input.val(val);
            }
        });
    };
    /**
     * 인증을 위한 폼 name 데이터 문자열
     * @param form : 데이터를 가져올 제이쿼리 폼
     */
    this.getInputString = function(form) {
        var obj = MegaboxUtil.Form.getFormObjData(form);
        var returnStr = '';

        $.map(obj, function(value, key) {
            returnStr += '^' + key + '|' + value;
        });

        return returnStr;
    };
    /**
     * 체크박스 및 라디오 버튼인지 여부
     * @param form : 제이쿼리 폼
     * @param name : 인풋 네임
     * @returns Boolean : true(존재), false(미존재)
     */
    var getInputCheckType = function(form, name) {
        var result;

        if($(form).find('input[type=radio][name=' + name + ']').length > 0) {
            result = true;
        } else if($(form).find('input[type=checkbox][name=' + name + ']').length > 0) {
            result = true;
        } else {
            result = false;
        }

        return result;
    };
    /**
     * 데이터 체크 함수
     * @param obj : 유효성 체크 Object
     * @param form : 제이쿼리 폼
     * @returns Boolean : true(정상), false(비정상)
     */
    this.validRegForm = function(obj, form) {
        var result = true;
        var target;

        $.each(obj, function(i, v) {
            if(v.target instanceof Array) {
                for(var j = 0; j < v.target.length; ++j) {
                    target = form? form.find(v.target[j]) : $(v.target[j]);

                    if(!validDataCheck(target, v.msg)) {
                        result = false;
                        return false;
                    }
                }
            } else {
                target = form? form.find(v.target) : $(v.target);

                if(!validDataCheck(target, v.msg)) {
                    result = false;
                    return false;
                }
                // 정규식 체크
                if(v.pattern) {
                    if(!MegaboxUtil.Form.vlidRegDataCheck(target, v.pattern, true)) {
                        result = false;
                        return false;
                    }
                }
                // 데이터 비교
                if(v.eq) {
                    if(target.val() != $(v.eq.target).val()) {
                        MegaboxUtil.Common.alert(v.eq.msg);

                        result = false;
                        return false;
                    }
                }
            }
        });
        return result;
    };
    // 등록 데이터 빈값 체크 함수
    var validDataCheck = function(target, msg) {
        var result = true;
        if(target.val().trim() == '' || target.val() == undefined) {
            var targetName = target.attr("name");

            result = false;

            if (targetName != "lentDe") { // 관람/대관일 focus제외
                target.focus();
            }

            MegaboxUtil.Common.alert(msg);
        }
        return result;
    };
    // 정규식 체크
    this.vlidRegDataCheck = function(target, ptn, alertType) {
        var msg = ptn.msg;
        var result = true;

        if(!new RegExp(pattern[ptn.id]).test(target.val())) {
            if(alertType) MegaboxUtil.Common.alert(msg);

            result = false;
        }

        return result;
    };

    /**
     * 비밀번호 유효성을 검사한다.
     * @author AJ
     * @param {string} sVal 비밀번호 문자열
     * @returns {boolean} 유효 여부
     */
    this.validatePwdString = function (sVal) {
        if(new RegExp(pwPattern).test(sVal)){
            return true;
        } else {
            return false;
        }
    };
};

var Movie = function() {
    var imgSvrUrl;
    var htmlData = '<li tabindex="0" class="no-img">' +
        '<div class="movie-list-info">' +
        '    <p class="rank" style="display: none">boxoRank<span class="ir">위</span></p>' +
        '    <img src="posterPathData" alt="movieNm" class="poster lozad" onerror="noImg(this)" />' +
        '    <div class="curation">' +
        '        <p class="film" style="display: none">필름 소사이어티</p>' +
        '        <p class="classic" style="display: none">클래식 소사이어티</p>' +
        '    </div>' +
        '    <div class="screen-type2">' +
        '        <p name="dbcScrean" style="display: none"><img src="/static/pc/images/common/btn/mov_top_tag_db.png" alt="dolby" /></p>' +
        '        <p name="mxScreen"  style="display: none"><img src="/static/pc/images/common/btn/mov_top_tag_mx.png" alt="mx" /></p>' +
        '    </div>' +
        '    <div class="movie-score">' +
        '        <a href="#" class="wrap movieBtn" data-no="movieNo" title="aTag_title">' +
        '            <div class="summary">movieSynopCn</div>' +
        '            <div class="my-score pointClass">' +
        '                <div class="preview">' +
        '                    <p class="tit">관람평</p>' +
        '                    <p class="number">admisYSpoint<span class="ir">점</span></p>' +
        '                </div>' +
        '            </div>' +
        '        </a>' +
        '    </div>' +
        '</div>' +
        '<div class="tit-area">' +
        '    <p class="movie-grade admisClass">admisText</p>' +
        '    <p title="movieNm" class="tit">movieNm</p>' +
        '</div>' +
        '<div class="rate-date">' +
        '    <span class="rate">예매율 boxoBokdRt&#37;</span>' +
        '    <span class="date">개봉일 rfilmDe</span>' +
        '</div>' +
        '<div class="btn-util">' +
        '    <button type="button" class="button btn-like" data-no="movieNo"><i title="보고싶어 intrstText" class="iconset ico-heart-toggle-gray intrstType"></i> <span>intrstCnt</span></button>' +
        '    <p class="txt movieStat1" style="display: none">상영예정</p>' +
        '    <p class="txt movieStat2" style="display: none">monthDe월 개봉예정</p>' +
        '    <p class="txt movieStat5" style="display: none">개봉예정</p>' +
        '    <p class="txt movieStat6" style="display: none">상영종료</p>' +
        '    <div class="case col-2 movieStat3" style="display: none">' +
        '        <a href="#" class="button purple bokdBtn" data-no="movieNo" title="영화 예매하기">예매</a>' +
        '        <a href="#" class="button purple img splBtn" data-no="movieNo"><img src="/static/pc/images/common/btn/mov_list_db_btn.png" alt="dolby 버튼" /></a>' +
        '    </div>' +
        '    <div class="case movieStat4" style="display: none">' +
        '        <a href="#" class="button purple bokdBtn" data-no="movieNo" title="영화 예매하기">예매</a>' +
        '    </div>' +
        '</div>' +
    '</li>';

    /**
     * 이미지 도메인 설정
     * @param url : 도메인 경로
     */
    this.setImgSvrUrl = function(url) {
        imgSvrUrl = url;
    };

    /**
     * 영화 목록 태그 생성
     * @param list : 영화 목록
     * @param target : html이 들어갈 제이쿼리 객체
     * @param pagingType : 페이징 여부
     * @param myLikeAt : 보고싶어 여부
     */
    this.createHtml = function(list, target, pagingType, myLikeAt) {
        var html, imgPath, pointClass, admisClass, admisText, intrstText, boxoBokdRt;
        var imgDomainUrl = imgSvrUrl || '';
        var liTarget;

        imgPathAr = [];

        // 태그 초기화
        if(!pagingType) MegaboxUtil.Movie.removeHtml(target);

        $.each(list, function(i, v) {
            html = htmlData.concat();
            imgPath = v.imgPathNm ? v.imgPathNm : '';
            boxoBokdRt = v.boxoBokdRt ? v.boxoBokdRt : 0;

            if(v.onairYn == 'MSC02' || v.specialType =='classic' || v.specialType =='film' || v.movienmSearchYn == 'Y' || v.festivalYn == 'Y') {
                html = html.replaceAll(/boxoRank/, ''); 	// 상영예정작, 필름, 클래식은 순위 없음(검색영화도 없음)
            } else {
                if(v.boxoRank) html = html.replaceAll(/boxoRank/, v.rowNum); // 박스오피스 순위
            }


            html = html.replaceAll(/posterPathData/, imgDomainUrl + nvl(v.imgPathNm).posterFormat('_420')); // 포스터 이미지
            html = html.replaceAll(/movieNm/, v.movieNm); // 영화명
            html = html.replaceAll(/movieSynopCn/, v.movieSynopCn); // 영화 시놉시스

            if(v.admisNSpoint > v.admisYSpoint) pointClass = 'smal'; // 관람평이 기대평보다 작을 경우
            else if(v.admisNSpoint < v.admisYSpoint) pointClass = 'big'; // 관람평이 기대평보다 큰 경우
            else pointClass = 'equa'; // 관람평과 기대평이 같은 경우

            html = html.replaceAll(/pointClass/, pointClass); // 관람평 비교 클래스
            html = html.replaceAll(/admisNSpoint/, v.admisNSpoint); // 기대평
            html = html.replaceAll(/admisYSpoint/, v.admisYSpoint); // 관람평

            if(v.admisClassCd == 'AD01') {
                admisClass = 'age-all';
                admisText = '전체 관람가';
            } else if(v.admisClassCd == 'AD02') {
                admisClass = 'age-12';
                admisText = '12세 이상 관람가';
            } else if(v.admisClassCd == 'AD03') {
                admisClass = 'age-15';
                admisText = '15세 이상 관람가';
            } else if(v.admisClassCd == 'AD04') {
                admisClass = 'age-19';
                admisText = '청소년 관람 불가';
            } else {
                admisClass = 'age-no';
                admisText = '미정';
            }

            html = html.replaceAll(/admisClass/, admisClass); // 관람등급 클래스
            html = html.replaceAll(/admisText/, v.admisText); // 관람등급 텍스트
            html = html.replaceAll(/boxoBokdRt/, boxoBokdRt); // 예매률

            if(v.rfilmDe != null) {
                html = html.replaceAll(/rfilmDe/, v.rfilmDe); // 개봉일
                html = html.replaceAll(/monthDe/, Number(v.rfilmDe.substr(5, 2))); // 예매가능 월
            } else {
                if(v.rfilmYm != null) {
                    html = html.replaceAll(/rfilmDe/, v.rfilmYm+' 월경'); // 개봉월
                    html = html.replaceAll(/monthDe/, Number(v.rfilmYm.substr(5, 2))); // 예매가능 월
                } else {
                    html = html.replaceAll(/rfilmDe/, ''); // 개봉월
                    html = html.replaceAll(/monthDe/, ''); // 예매가능 월
                }
            }



            /*
            if(v.rfilmDe != null) {
                html = html.replaceAll(/rfilmDe/, v.rfilmDe); // 개봉일
                //html = html.replaceAll(/monthDe/, Number(v.rfilmDe.substr(5, 2))); // 예매가능 월
            } else {
                if(v.rfilmYm != null) {
                    html = html.replaceAll(/rfilmDe/, v.rfilmYm+' 월경'); // 개봉월
                    //html = html.replaceAll(/monthDe/, Number(v.rfilmYm.substr(5, 2))); // 예매가능 월
                } else {
                    html = html.replaceAll(/rfilmDe/, ''); // 개봉월
                    html = html.replaceAll(/monthDe/, ''); // 예매가능 월
                }
            }
            if(v.rfilmYm != null) {
                html = html.replaceAll(/monthDe/, Number(v.rfilmYm.substr(5, 2))); // 예매가능 월
            } else {
                html = html.replaceAll(/monthDe/, Number(v.rfilmDe.substr(5, 2))); // 예매가능 월
            }
*/



            if(v.intrstAt == 'Y' ||
                    myLikeAt) {
                intrstText = '함';
                html = html.replaceAll(/intrstType/, 'on'); // 보고싶어 여부
            } else {
                intrstText = '안함';
            }

            html = html.replaceAll(/intrstText/, intrstText); // 보고싶어 타이틀명

            var s_intrstCnt = '';
            if (v.intrstCnt > 999) {
                s_intrstCnt = Math.floor((v.intrstCnt/1000) * 10)/10  + 'k';
            } else {
                s_intrstCnt = v.intrstCnt;
            }

            html = html.replaceAll(/intrstCnt/, s_intrstCnt); // 보고싶어 카운트  v.intrstCnt.format()
            html = html.replaceAll(/movieNo/, v.rpstMovieNo); // 대표 영화번호

            html = html.replaceAll(/aTag_title/, v.movieNm +' 상세보기'); // 대표 영화번호

            target.append(html);
            liTarget = target.find('li:last');

            if(myLikeAt) { // 나의 메가박스 보고싶어 리스트시
              liTarget.find('.rate-date').hide();
              //liTarget.find('.movie-score').hide();
            }

            // 상영예정작 관람평 미노출
            if (v.filmAfAt == 'Y') {
                liTarget.find('.my-score').hide();
            }

            if(v.boxoRank && !myLikeAt) liTarget.find('.rank').show(); // 박스오피스 순위 존재시
            if(v.filmAt == 'Y' && v.specialType !='classic') liTarget.find('.film').show(); // 필름 소사이어티 여부
            if(v.classicAt == 'Y' && v.specialType !='film') liTarget.find('.classic').show(); // 클래식 소사이어티 여부
            if(v.mxTheabAt == 'Y') liTarget.find('[name=mxScreen]').show(); // MX관 상영 여부
            if(v.dbcTheabAt == 'Y') liTarget.find('[name=dbcScrean]').show(); // 돌비관 상영 여부

            if (v.movieStatCd == 'MSC01' && v.dbcTheabAt == 'Y' && v.bokdAbleYn == 'Y') liTarget.find('.movieStat3').show(); // 예매, dolby 예매 가능
            else if(v.movieStatCd == 'MSC01' && v.bokdAbleYn == 'Y') liTarget.find('.movieStat4').show(); // 예매 가능
            else if(v.movieStatCd == 'MSC02' && v.dbcTheabAt == 'Y' && v.rfilmDeReal != null) liTarget.find('.movieStat3').show(); // 예매, dolby 예매 가능
            else if(v.movieStatCd == 'MSC02' && v.bokdAbleYn == 'Y' && v.rfilmDeReal != null) liTarget.find('.movieStat4').show(); // 예매 가능
            else if(v.movieStatCd == 'MSC02' && v.bokdAbleYn == 'N' && v.rfilmDeReal != null) liTarget.find('.movieStat5').show(); // 개봉예정
            else if(v.movieStatCd == 'MSC02' && v.bokdAbleYn == 'N' && v.rfilmDeReal == null && v.rfilmYm != null) liTarget.find('.movieStat2').show(); // 월 개봉예정
            else if(v.movieStatCd == 'MSC03') liTarget.find('.movieStat6').show(); // 상영종료
            else liTarget.find('.movieStat1').show(); // 상영예정 : 'MSC01' 이면서 bokdAbleYn=N

        });

        if(myLikeAt){
            $(".tit-area .tit").each(function(idx){
                var htmlMovieNm = $(this).html();
                $(this).html("<a href='javaScript:void(0)' title='"+ htmlMovieNm + "'>"+ htmlMovieNm +"</a>");
          });
        }

        //movieImgLoad(); // 이미지 지연 로딩
        addMouseEvent(target,myLikeAt); // 영화 마우스 이벤트
    };

    /**
     * 영화 목록 태그 삭제
     */
    this.removeHtml = function(target) {
        target.empty();
    };

    /**
     * 영화 이미지 지연 로딩
     */
    var movieImgLoad = function() {
      // 이미지 지연 로딩 설정
    lozad('.lozad' , {
      load: function(img) {
        img.src = img.dataset.src; // 이미지 설정
      }
    }).observe();

    // 이미지 완료 후 상단 삼각형 히든 클래스 삭제
    $('.lozad').off().on('load', function() {
      $(this).parents('li').removeClass('no-img');
    });
  };

    /**
     * 영화 목록 마우스 이벤트
     */
    var addMouseEvent = function(target, myLikeAt) {
        // 영화 목록 이벤트

        target.find('.movie-list-info').off().on({
            mouseenter: function() {
                if(!myLikeAt)
                    $(this).find('.movie-score').finish().addClass('on').animate({opacity: 1}, 300);
                else
                    $(this).find('.movie-score').finish().addClass('on');
            },
            mouseleave: function() {
                if(!myLikeAt) {
                    $(this).find('.movie-score').finish().animate({opacity: 0}, 300, function() {
                        $(this).removeClass('on');
                    });
                }
            },
            focus: function() {
                if(!myLikeAt)
                    $(this).find('.movie-score').finish().addClass('on').animate({opacity: 1}, 300);
            },
            blur: function() {
                if(!myLikeAt) {
                    $(this).find('.movie-score').finish().animate({opacity: 0}, 300, function(){
                        $(this).removeClass('on');
                    });
                }
            }
        });

        // 보고싶어 클릭
        $('.btn-like').off().on('click', function() {
            updateMovieHeart(this);
        });

        // 예매 클릭
        $('.bokdBtn').off().on('click', function(e) {
          e.preventDefault();

            moveBokdPage($(this).data('no'));
        });

        // 특별관 예매 클릭
        $('.splBtn').off().on('click', function(e) {
          e.preventDefault();

            moveBokdPage($(this).data('no'), true);
        });

        // 영화 상세 페이지 이동
        $('.movieBtn').off().on('click', function(e) {
            e.preventDefault();

            var no = $(this).data('no');

            $.ajaxMegaBox({
                url: '/on/oh/oha/Movie/selectMovieInfoCheck.do',
                data: JSON.stringify({
                  rpstMovieNo: no
                }),
                success: function(d) {
                    if(d.result) {
                      moveMovieDetailPage(no, true);
                    } else {
                      gfn_alertMsgBox('영화정보가 존재하지 않습니다.');
                    }
                }
            });
        });

        if(myLikeAt){
            $('.tit-area .tit').off().on('click', function(e) {
                $(this).parent().parent().find('.movieBtn').trigger("click");
            });
        }

    };

    // 보고싶어 등록, 삭제 처리
    var updateMovieHeart = function(target) {
        $.ajaxMegaBox({
            url: '/on/oh/oha/Movie/mergeMovieHeart.do',
            data: JSON.stringify({ rpstMovieNo: $(target).data('no')}),
            sessionAt:true,
            success: function (d) {
                var resultMap = d.resultMap;

                if(resultMap.msg == 'sessionFail')
                    return gfn_alertMsgBox('로그인 후 이용가능한 서비스입니다.');

                if(resultMap.rowStatCd == 'D'){
                    $(target).attr('title', '보고싶어 안함');
                    $(target).find('i').removeClass("on");

                } else {
                    $(target).attr('title', '보고싶어 함');
                    $(target).find('i').addClass("on");
                }


                var s_intrstCnt = '';
                if (resultMap.intrstCnt > 999) {
                    s_intrstCnt = Math.floor((resultMap.intrstCnt/1000) * 10)/10  + 'k';
                } else {
                    s_intrstCnt = resultMap.intrstCnt;
                }
                //$(target).find('span').html(resultMap.intrstCnt.format());
                $(target).find('span').html(s_intrstCnt);


                // 보고싶어 후 처리 함수 존재시 실행
                if(window.fn_selectMovieList) fn_selectMovieList();
            }
        });
    };

    /**
     * 예매 페이지 이동
     */
    var moveBokdPage = function(movieNo, splType) {
        var form = MegaboxUtil.Form.createForm();
        form.append($('<input>').attr({ 'type': 'hidden', 'name': 'rpstMovieNo', 'value': movieNo }));
        form.attr('action', '/booking');

        // 특별관 예매 여부
        if(splType) form.append($('<input>').attr({ 'type': 'hidden', 'name': 'theabKindCd1', 'value': 'DBC'}));

        form.submit();
    };

    /**
     * 영화 상세 페이지 이동
     */
    var moveMovieDetailPage = function(movieNo) {
        var form = MegaboxUtil.Form.createForm();
        form.append($('<input>').attr({ 'type': 'hidden', 'name': 'rpstMovieNo', 'value': movieNo }));
        form.attr('method', 'get');
        form.attr('action', '/movie-detail');
        form.submit();
    };

    /**
     * 내가 본 영화 레이어 호출 버튼 이벤트
     */
    this.bindMyViewMovieEvent = function(targetName, callbackFn) {
        MegaboxUtil.Common.bindNumberTypeEvent();

        // 레이어 호출 버튼 이벤트
        $('#' + targetName).off().on('click', function(e) {
            if($('#isLogin').val() != 'Y') {
                gfn_alertMsgBox('로그인후 이용 가능한 서비스입니다.');

                return false;
            }
        });

        bindMyViewMovieActionEvent();
    };

    /**
     * 내가 본 영화 등록 버튼 이벤트
     */
    var bindMyViewMovieActionEvent = function() {
        $('#movie_regi').val('');
        $('#movie_regi').next().off().on('click', function() {
            var tranNo = $('#movie_regi').val();
            if(tranNo == '') return gfn_alertMsgBox('거래번호 또는 예매번호를 입력해주세요.');

            $.ajaxMegaBox({
                 url: '/on/oh/ohb/Movie/insertAdmisMovie.do',
                 data: JSON.stringify({
                     tranNo: tranNo
                 }),
                 clickLmtChk: true, //중복클릭 방지 실행
                 success: function(d) {
                     if(d.result == 'admisY') {
                         gfn_alertMsgBox('이미 등록된 영화입니다.');
                     } else if(d.result == 'noTranNo') {
                         gfn_alertMsgBox('존재하지않는 거래번호 또는 예매번호 입니다.');
                     } else if(d.result == 'playEnd') {
                         gfn_alertMsgBox('본 영화는 상영시간 종료 후 등록하실 수 있습니다.');
                     } else if(d.result == 'complete') {
                         gfn_alertMsgBox('더 이상 등록할 수 없는 거래번호 또는 예매번호 입니다.');
                     } else {
                         fn_callbackInsertMovies(d.rpstMovieNo);

                         var options = {};
                         // 본영화 등록 후 한줄평 페이지 이동 처리
                         if (location.pathname.indexOf('/movie-detail') === -1) { // 나의메가박스, 무비스토리
                             options.msg = '본 영화 등록이 완료되었습니다.\n관람하신 영화에 대한 관람평을 지금 작성하시겠습니까?';
                             options.confirmFn = function () {
                                 if (d.rpstMovieNo) {
                                     location.href = '/movie-detail/comment?rpstMovieNo=' + d.rpstMovieNo;
                                 }
                             };
                             gfn_confirmMsgBox(options);
                         } else { // 영화상세 페이지인 경우 리다이렉트 시키지 않는다.
                             options.msg = '영화가 등록 되었습니다.';
                             gfn_alertMsgBox(options);
                         }
                     }
                 },complete: function(xhr){
                	 $('#movie_regi').val('');
                     clearLmt(); //중복제한 초기화
                 }
            });
        });
    }
};

//본영화 등록 후 콜백함수
function fn_callbackInsertMovies(rpstMovieNo){
    $('#movie_regi').val('');
    if($('#rpstMovieNo').val() == rpstMovieNo){
    	$(".btn-modal-open.oneWrtBtn").attr("href", "#layer_regi_reply_review");
    	gMbAdmisAt = 'Y';
    }
    $('#saw_movie_regi .btn-modal-close').trigger("click");
    if(MegaboxUtil.MovieStory != undefined)MegaboxUtil.MovieStory.createSeenMovie();
    if($(".box-border.link-movie-story em").size() == 4) $(".box-border.link-movie-story em:eq(0)").html(Number($(".box-border.link-movie-story em:eq(0)").html())+1);
};

var MoviePost = function() {
    var masonryTarget;
    var currentPage = 1;
    var recordCountPerPage = 12;

    /**
     * 무비포스트 목록 생성
     * @param  target : 무비포스트 리스트가 추가될 부모 태그
     * @param  option : data(리스트 데이터), loginId(로그인 아이디), moreTarget(더보기 버튼 아이디)
     * @param  paging : 무비포스트 페이징 여부
     */
    this.createMoviePostList = function(target, option, paging, backScreen) {
        var list = option.data || null;
        var html, onClass, isMy, imgNm;
        var totCnt = 0;
        var mbLoginId = option.loginId || '';
        var imgSvrUrl = option.imgSvrUrl || '';
        var moreBtn = option.moreTarget ? $(document).find('#' + option.moreTarget) : $(document).find('.more-movie-list');
        var loginFullId, loginId, mbNo;

        // 페이징이 아닐시에만 태그 초기화
        if(!paging) {
            target.find('.grid-item').remove(); // 태그 삭제

            // 라이브러리에 저장된 데이터 삭제
            $.each(target.find('.grid-item'), function(i , v) {
                target.masonry('remove', v);
            });
        }
        else {
            //masonryTarget = false;
        }

        //상세보기 url 호출시
        if( option.moviePostNo != null && option.moviePostNo != '' ){
            html = '';
            html += '<div class="" style="display:none;">';
            html += '	<a href="#layer_post_detail" class="post-detailPopup btn-modal-open2 target" w-data="850" h-data="auto" data-no="'+ option.moviePostNo +'" data-url="" title="상세보기">';
            //html += '		<img src="' + imgSvrUrl + imgNm + '" alt="' + v.moviePostMovieTitle + '" onerror="noImg(this);"> ';
            html += '		<img src="/static/pc/images/common/bg/bg-noimage-notmain.png" alt="상세보기 이미지" onerror="noImg(this);">';
            html += '	</a>';
            html += '</div>';
            target.append(html);
        }

        $.each(list, function(i, v) {
            onClass = v.likeYn == 'Y' ? ' on' : '';
            currentPage = v.currentPage;
            totCnt = v.totCnt;
            loginId = v.loginId ? v.loginId : v.mbNm;
            //loginFullId = v.loginFullId ? v.loginFullId : v.fullMbNm;

            html = '';
            html += '<div class="grid-item">';
            html += '    <div class="wrap">';

            // 가림여부 Y일시
            if(v.postMaskAt == 'Y') {
                var disp_txt = "";
                if (v.postMaskResnCd == 'SPOL') {
                    disp_txt = "영화 내용에 대한 스포일러가 포함되어 있어 내용을 표시하지 않습니다.";
                } else if (v.postMaskResnCd == 'SLAN') {
                    disp_txt = "비방,욕설,선정적 내용이 포함되어 있어 내용을 표시하지 않습니다.";
                } else if (v.postMaskResnCd == 'ADVT') {
                    disp_txt = "광고, 홍보성 내용이 포함되어 있어 내용을 표시하지 않습니다.";
                } else if (v.postMaskResnCd == 'NOTA') {
                    disp_txt = "작성된 내용이 무의미한 문자의 나열로 구성되어 내용을 표시하지 않습니다.";
                } else {
                    disp_txt = "관리자가 내용의 표시를 차단했습니다.";
                }
                html += '<div class="warning">';
                html += '    <div class="table">';
                html += '        <div class="inner-text">';
                html += '            <i class="iconset ico-ping-triangle"></i>';
                html += '            <p>'+disp_txt+'</p>';
                html += '        </div>';
                html += '    </div>';
                html += '</div>';
            }

            if(v.moviePostImgDivCd == 'MOVIEPOST')  {
                imgNm = v.imgPath;
            } else {
                imgNm = nvl(v.imgPath).posterFormat('_230');
            }

            html += '        <div class="img">';
            html += '            <a href="#layer_post_detail" title="무비포스트 상세보기" class="post-detailPopup btn-modal-open2"  w-data="850" h-data="auto" data-no="' + v.moviePostNo + '" data-row="' + v.rowNum  + '" data-tot="' + v.totCnt  + '" data-url="' + backScreen + '"><img src="' + imgSvrUrl + imgNm + '" alt="' + v.moviePostMovieTitle + '" onerror="noImg(this);"> /></a>';
            html += '        </div>';
            html += '        <div class="cont">';
            html += '            <div class="writer">';
            html += '                <a href="#" title="'+ loginId +'님의 무비포스트 보기" class="moviePostId" data-id="' + v.mbUid + '">' + loginId + '</a>';

            if(v.isMy == 'Y') html += '<p class="my">my</p>';

            html += '            </div>';
            if( v.maniaAt == 'Y' || v.edtpikAt == 'Y'){
            //	html += '            <a href="#" class="link moviePostBtn" data-no="' + v.moviePostNo + '" data-row="' +v.rowNum  + '" data-tot="' + v.totCnt + '">';
                html += '            <a href="#layer_post_detail" title="무비포스트 상세보기" class="link btn-modal-open2 post-detailPopup" w-data="850" h-data="auto" data-no="' + v.moviePostNo + '" data-row="' +v.rowNum  + '" data-tot="' + v.totCnt + '">';
                html += '                <div class="label">';

                if(v.maniaAt == 'Y') html += '<p class="mania">Movie mania</p>';
                if(v.edtpikAt == 'Y') html += '<p class="pick">Editor’s Pick</p>';

                html += '                </div>';
                html += '            </a>';
            }

            html += '            <a href="/movie-detail?rpstMovieNo=' + v.rpstMovieNo + '" title="'+v.moviePostMovieTitle+' 상세보기">';
            html += '                <p class="tit">' + v.moviePostMovieTitle + '</p>';
            html += '            </a>';

            html += '            <a href="#layer_post_detail" title="무비포스트 상세보기" class="link btn-modal-open2 post-detailPopup" w-data="850" h-data="auto" data-no="' + v.moviePostNo + '" data-row="' +v.rowNum  + '" data-tot="' + v.totCnt + '">';
            if (v.moviePostImgDesc == null) {
                html += '                <p class="txt">' + v.moviePostImgDesc + '</p>';
            } else {
                html += '                <p class="txt">' + v.moviePostImgDesc.replaceAll('\n', '<br>') + '</p>';
            }


            html += '                <p class="time">' + v.fstRegDt + '</p>';
            html += '            </a>';
            html += '            <div class="condition">';
//			자기자신은 추천 못하도록
//			if(v.isMy == 'Y') html += '                <button type="button" class="btn-like"             data-no="' + v.moviePostNo + '"><i class="iconset ico-like' + onClass + '">좋아요 수</i> <span class="none">' + v.postRcmmCnt + '</span></button>';
//			else              html += '                <button type="button" class="btn-like postLikeBtn" data-no="' + v.moviePostNo + '"><i class="iconset ico-like' + onClass + '">좋아요 수</i> <span class="none">' + v.postRcmmCnt + '</span></button>';
            html += '                <button type="button" class="btn-like postLikeBtn listBtn jsMake" data-no="' + v.moviePostNo + '"><i class="iconset ico-like' + onClass + '">좋아요 수</i> <span class="none">' + v.postRcmmCnt + '</span></button>';

            //html += '                <a href="#" class="moviePostRlyBtn" data-no="' + v.moviePostNo + '" data-row="' + v.rowNum  + '" data-tot="' + v.totCnt + '"><i class="iconset ico-reply">댓글 수</i> ' + v.moviePostRlyCnt + '</a>';
            html += '                <a href="#layer_post_detail"  title="댓글 작성하기" class="link btn-modal-open2 post-detailRlyPopup"  w-data="850" h-data="auto" data-no="' + v.moviePostNo + '" data-row="' + v.rowNum  + '" data-tot="' + v.totCnt + '"><i class="iconset ico-reply">댓글 수</i> ' + v.moviePostRlyCnt + '</a>';
            html += '            </div>';
            html += '        </div>';
            html += '    </div>';
            html += '</div>';

            target.append(html);
        });

        // 라이브러리 정렬 설정
        if(!masonryTarget) {
            masonryTarget = target.masonry({
                itemSelector: '.grid-item',
                columnWidth: 230,
                gutter : 60
            });
        } else {
            var startNo = recordCountPerPage * (currentPage - 1)

            $.each(target.find('.grid-item'), function(i , v) {
                if(i >= startNo){
                    target.masonry('appended', v);
                }
            });

            masonryTarget.masonry('layout');
        }

        if(recordCountPerPage < totCnt) moreBtn.show();
        else moreBtn.hide();

        bindMouseEvent();
    };

    /**
     * 무비포스트 버튼 이벤트
     */
    var bindMouseEvent = function() {
        // 무비포스트 좋아요
        $('.postLikeBtn.jsMake').off().on('click', function() {
            var idx = $('.postLikeBtn').index(this);
            $.ajaxMegaBox({
                url: '/on/oh/oha/Movie/mergeMoviePostHeart.do',
                data: JSON.stringify({
                    artiNo: $(this).data('no'),
                    artiDivCd: 'MOPO'
                }),
                sessionAt:true,
                success: function (d) {
                    var resultMap = d.resultMap;

                    if(resultMap.msg == 'sessionFail') return gfn_alertMsgBox("로그인 후 이용가능한 서비스입니다.");

                    if(resultMap.rowStatCd == 'D') $('.postLikeBtn').eq(idx).find('i').removeClass('on');
                    else $('.postLikeBtn').eq(idx).find('i').addClass('on');

                    $('.postLikeBtn').eq(idx).find('.none').text(resultMap.likeCnt);
                }
            });
        });

        //무비포스트 클릭 시(레이어팝업 호출)
        $('.post-detailPopup').on('click', function(e){
            fn_postDetail($(this).data('no'),'post', $(this).data('url'));

        });

        //무비포스트 클릭 시(레이어팝업 호출)
        $('.post-detailRlyPopup').on('click', function(e){
            fn_postDetail($(this).data('no'),'rly', $(this).data('url'));


        });

        // 무비포스트 클릭
        $('.moviePostBtn').off().on('click', function(e) {
            e.preventDefault();

            var scrollTop = $(document).scrollTop();
            var topSorting, orderSorting;

            if($('.sorting button.on').attr('sort-type') != '') {
                orderSorting = $('.sorting button.on').attr('sort-type');
            }

            if($('.tab-sorting .on').data('type') != '') {
                topSorting = $('.tab-sorting .on').data('type');
            }

            var form = MegaboxUtil.Form.createForm();
            /*form.append('<input type="hidden" name="moviePostNo" value="' + $(this).data('no') + '">');
            form.append('<input type="hidden" name="rowNum" value="' + $(this).data('row') + '">');
            form.append('<input type="hidden" name="totCnt" value="' + $(this).data('tot') + '">');*/
            form.append('<input type="hidden" name="tabType" value="' + $('#tabType').val() + '">');

            form.append('<input type="hidden" name="scrollTop" value="' + scrollTop + '">');
            form.append('<input type="hidden" name="currentPage" value="' + currentPage + '">');
            form.append('<input type="hidden" name="recordCountPerPage" value="' + recordCountPerPage + '">');
            form.append('<input type="hidden" name="topSorting" value="' + topSorting + '">');
            form.append('<input type="hidden" name="orderSorting" value="' + orderSorting + '">');
            form.append('<input type="hidden" name="ibxMovieNmSearch" value="' + $('#ibxMovieNmSearch').val() + '">');
            form.append('<input type="hidden" name="pageType" value="' + $('#pageType').val() + '">');
            form.append('<input type="hidden" name="onairYn" value="' + $('#onairYn').val() + '">');

            form.attr('method', 'post');
            //form.attr('action', '/moviepost/detail');
            form.attr('action', '/moviepost/detail?moviePostNo=' + $(this).data('no') + '&rowNum=' + $(this).data('row') + '&totCnt=' + $(this).data('tot'));
            form.submit();
        });

        // 무비포스트 댓글 클릭 --   기존 이벤트 주석처리
    /*	$('.moviePostRlyBtn').off().on('click', function(e) {
            e.preventDefault();

            var form = MegaboxUtil.Form.createForm();
            form.append('<input type="hidden" name="moviePostNo" value="' + $(this).data('no') + '">');
            form.append('<input type="hidden" name="rowNum" value="' + $(this).data('row') + '">');
            form.append('<input type="hidden" name="totCnt" value="' + $(this).data('tot') + '">');
            form.attr('method', 'get');
            form.attr('action', '/moviepost/detail#rly');
            form.submit();
        });
*/
        // 무비포스트 아이디 클릭
        $('.moviePostId').off().on('click', function(e) {
            e.preventDefault();

            var form = MegaboxUtil.Form.createForm();
            form.append('<input type="hidden" name="moviePostId" value="' + $(this).data('id') + '">');
            form.attr('action', '/moviepost/all');
            form.submit();
        });
    };
};

var Share = function() {

    /**
     * 페이스북 초기화
     */
    var facebookInit = function() {

        try {

            FB.init({
                appId: $('#fbAppId').attr('content')
                , status: true
                , cookie: true
                , xfbml: true
            });

        } catch(e) {
            console.log("facebookInit Exception");
        }
    };

    /**
     * SNS 초기화
     */
    this.init = function() {
        /*$('.btn-sns, .btn.tooltip.click, .btn-common-share').off().on('click', function(e) {
            e.preventDefault();

            var option = {};

            if($(this).attr('class').indexOf('btnSns') > -1) {
                option = {
                    type: 'movie',
                    img: location.host + $('.poster img').attr('src'),
                    title: $('.movie-detail-cont .title').text(),
                    desc: $('.movie-summary.infoContent .txt').text()
                }
            }

            $('.tooltip-layer, .tipPin, .btn-sns-share-wrap').animate({ opacity: 1, display: 'block', complete: function() {
                bindClickEvent(option);
            }});
        });*/

        bindClickEvent();
        //facebookInit();
    }

    /**
     * 공유하기 버튼 클릭 이벤트
     */
    var bindClickEvent = function(option) {
        $('.tooltip-layer, .tipPin').css('z-index', 302);
        $('.btn-sns-share-group button').off().on('click', function(e) {
            e.preventDefault();

            var classStr = $(this).attr('class');

            if(classStr.indexOf('kakao') > -1) { // 카카오톡
                if(!MegaboxUtil.Common.isMobile() && !MegaboxUtil.Common.isApp()) {
                    MegaboxUtil.Common.alert('앱에서만 사용 가능합니다.');
                } else {
                    MegaboxUtil.Common.alert('준비중입니다.');
                }
            } else if(classStr.indexOf('face') > -1) { // 페이스북
                MegaboxUtil.Share.facebook(option);
            } else if(classStr.indexOf('band') > -1) { // 밴드
                MegaboxUtil.Share.band(option);
            } else if(classStr.indexOf('twitter') > -1) { // 트위터
                MegaboxUtil.Share.twitter(option);
            } else { // 링크 공유
                MegaboxUtil.Share.copyUrl();
            }

            // 공유하기 후 토글처리
            $(this).closest('.sns-share').find('.btn-sns-share-wrap').toggleClass('on');
        });

        // 공유하기 밖 영역 클릭시 공유하기창 닫기
        $(document).on('click', function(e) {
            var target = $(e.target);

            if(target.parents('.sns-share').length == 0) {
                $('.btn-sns-share-wrap').removeClass('on');
            }

            //알림함 포커스 아웃 클릭시 닫기
            if(target.parents('.after').length == 0) {
                $('.layer-header-notice').removeClass('on');
            }

            //상단 나의 메가박스 정보 포커스 아웃 클릭시 닫기
            if(	target.parents('#layer_mymega2').length == 0
                && target.parents('.link-area').length == 0
                && $('#header .link-area .header-open-layer.btn-layer-mymega').hasClass("on")) {
                $('#header .link-area .header-open-layer.btn-layer-mymega').removeClass("on")
                $('#layer_mymega2').removeClass('on');
            }

            //상단 좌측 영화검색 포커스 아웃 클릭시 닫기
            if(	target.parents('#layer_header_search').length == 0
                    && target.parents('.link-area').length == 0
                    && $('#header .link-area .header-open-layer.btn-layer-search').hasClass("on")) {
                $('#header .link-area .header-open-layer.btn-layer-search').removeClass("on")
                $('#layer_header_search').removeClass('on');
            }

        });
    };

    /**
     * 클립보드 복사
     */
    this.copyUrl = function() {
        var url = location.href;

        // 영화 상세일시 공유 URL 설정
        if(url.indexOf('selectMovieDetail.do') > -1) {
            url = $('#fbUrl').attr('content');
        }

        var tmpTextarea = document.createElement('textarea');
        tmpTextarea.style.position = "absolute";
        tmpTextarea.style.left = "-9999px";
        tmpTextarea.style.top = "0";
        tmpTextarea.value = url.replace(/</g, '&lt;').replace(/>/g, '&gt;');

        document.body.appendChild(tmpTextarea);
        tmpTextarea.select();
        tmpTextarea.setSelectionRange(0, 9999);  // 셀렉트 범위 설정

        document.execCommand('copy');
        document.body.removeChild(tmpTextarea);

        MegaboxUtil.Common.alert('복사되었습니다.');

        /*if(window.clipboardData == undefined) { // etc
            var $tmpDiv = $('<div style="position:absolute;top:-1000px;left:-1000px;">' + url.replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</div>').appendTo('body')
            ,range=document.createRange()
            ,selection=null;

            range.selectNodeContents($tmpDiv.get(0));
            selection=window.getSelection();
            selection.removeAllRanges();
            selection.addRange(range);


            function jsCopyLink(copyText) {

                var tmpTextarea = document.createElement('textarea');
                tmpTextarea.value = copyText;

                document.body.appendChild(tmpTextarea);
                tmpTextarea.select();
                tmpTextarea.setSelectionRange(0, 9999);  // 셀렉트 범위 설정

                document.execCommand('copy');
                document.body.removeChild(tmpTextarea);

            }

            window.addEventListener('copy', function(e) {
                e.preventDefault();
                e.clipboardData.setData('text/plain', url);
            })

            if(document.execCommand('copy', false, null)) {
                MegaboxUtil.Common.alert('복사되었습니다.');
            } else {
                window.prompt('Copy to clipboard: Ctrl+C, Enter', url);
            }

            $tmpDiv.remove();
        } else { // ie
            window.clipboardData.setData('Text', url)
            MegaboxUtil.Common.alert('복사되었습니다.');
        }*/
    }

    /**
     * 페이스북 공유
     */
    this.facebook = function(option) {
        if (MegaboxUtil.Common.isApp()) {
            //도메인 주소 필수
            if( $("#fbUrl").attr("content").indexOf('/') == 0 ) {
                $("#fbUrl").attr("content", location.protocol + '//' + document.domain + $("#fbUrl").attr("content"));
            }

            var oData = {
                    type: 'facebook',
                    url: $('#fbUrl').attr('content'),
                    image: $('#fbImg').attr('content'),
                    title: $('#fbTitle').attr('content'),
                    description: $('#fbDtls').attr('content')
            }
            AppHandler.Common.share(oData);
        }
        else {

        	//도메인 주소 필수
            if( $("#fbUrl").attr("content").indexOf('/') == 0 ) {
                $("#fbUrl").attr("content", location.protocol + '//' + document.domain + $("#fbUrl").attr("content"));
            }

            var url = "http://www.facebook.com/sharer/sharer.php?u="+$("#fbUrl").attr("content");
            var top = (document.body.offsetHeight / 2) - 215;
            var left = (document.body.offsetWidth / 2) - 350;

            window.open(url, 'facebookShare', 'width=555, height=450, toolbar=no, left=' + left + ', top=' + top);

            /*try {
                //도메인 주소 필수
                if( $("#fbUrl").attr("content").indexOf('/') == 0 ) {
                    $("#fbUrl").attr("content", location.protocol + '//' + document.domain + $("#fbUrl").attr("content"));
                }

                FB.ui(
                    {
                        method        		: 'share',
                        action_type			: 'og.shares',
                        action_properties	: JSON.stringify({
                            object: {
                                'og:title': 		$("#fbTitle").attr("content")
                                , 'og:description':	$("#fbDtls").attr("content")
                                , 'og:image': 		$("#fbImg").attr("content")
                                , 'og:url': 		$("#fbUrl").attr("content")
                            }
                        })
                    },
                      // callback
                      function(response) {
                        if (response && !response.error_message) {
                          //gfn_alertMsgBox('성공적으로 공유되었습니다.');
                        } else {
                          //gfn_alertMsgBox('Error while posting.');
                        }
                      }
                );
            } catch(e) {
                console.log(e);
            }*/
        }
    };

    /**
     * 트위터 공유
     */
    this.twitter = function(option) {
        var text = $('#fbTitle').attr('content');
        if (MegaboxUtil.Common.isApp()) {
            var oData = {
                    type: 'twitter',
                    text: text,
                    url: location.href
            };
            AppHandler.Common.share(oData);
        }
        else {
            var url = 'https://twitter.com/intent/tweet?text=' + encodeURIComponent(text) + '&url=' + encodeURIComponent(location.href);
            var top = (document.body.offsetHeight / 2) - 215;
            var left = (document.body.offsetWidth / 2) - 350;

            window.open(url, 'twitterShare', 'width=700, height=430, toolbar=no, left=' + left + ', top=' + top);
        }
    };

    /**
     * 밴드 공유
     */
    this.band = function(option) {

        if(option && option.type == 'movie') { // 영화 일시 영화 정보 설정
            $('#fbImg').attr('content', option.img);
            $('#fbTitle').attr('content', option.title);
            $('#fbDtls').attr('content', option.desc);
        }

        var dtls = $('#fbDtls').attr('content')
        if( dtls.length > 100 ){
            dtls = dtls.substr(0,100) + "...";
        }

        //도메인 주소 필수
        if( $("#fbUrl").attr("content").indexOf('/') == 0 ){
            $("#fbUrl").attr("content", location.protocol + '//' + document.domain + $("#fbUrl").attr("content"));
        }

        var body = $('#fbUrl').attr('content') + '\n' + $('#fbTitle').attr('content') + '\n' + gfn_charToHtml(dtls);

        if (MegaboxUtil.Common.isApp()) {
            var oData = {
                    type: 'band',
                    text: body,
                    route: location.href
            };
            AppHandler.Common.share(oData);
        }
        else {
            var url = 'http://www.band.us/plugin/share?body=' + encodeURIComponent(body) + '&route=' + location.href;
            var top = (document.body.offsetHeight / 2) - 215;
            var left = (document.body.offsetWidth / 2) - 350;

            window.open(url, 'bandShare', 'width=700, height=430, toolbar=no, left=' + left + ', top=' + top);
        }
    };
};

var MegaboxUtil = new function() {
    this.Common = new Common();
    this.Form = new Form();
    this.Movie = new Movie();
    this.MoviePost = new MoviePost();
    this.Share = new Share();
}

// Timers
var Timers = function() {
    this.compTime = { "Y" : 60 * 60 * 24 * 365
                    , "M" : 60 * 60 * 24 * 30
                    , "D" : 60 * 60 * 24
                    , "H" : 60 * 60
                    , "m" : 60
                    , "s" : 1
                    };
    this.event               = {};
    this.event.onRunStart    = null;
    this.event.onRunCallBack = null;
    this.event.onComplete    = null;
    this.param               = {};
    this.param.compFmt       = {};


    this.fn_init = function(setting){
        this.param.runKey        = null;
        this.param.runDateTime   = setting.runDateTime.toDateTime();
        this.param.compFmt       = {};
        this.param.exeVal        = setting.exeVal;
        this.param.exeType       = setting.exeType;
        this.param.exeIntrvl     = setting.exeIntrvl;
        this.event.onRunStart    = setting.onRunStart;
        this.event.onRunCallBack = setting.onRunCallBack;
        this.event.onComplete    = setting.onComplete;
        return isNaN( this.param.runDateTime );
    };
    this.fn_initRun = function(sysDT) {
        this.param.sysDateTime  = sysDT.toDateTime();
        this.param.diffTime     = this.param.runDateTime - this.param.sysDateTime;
        this.param.startDate    = new Date();
        return this.diffTime;
    }
    this.fn_DiffFmt = function (mSecnd){
        var secnd = mSecnd / 1000;
        var keyList = Object.keys(this.compTime);
        var compFmt = {};
        for ( var i = 0 ; i < keyList.length ; i ++ ){
            if ( secnd >= this.compTime[keyList[i]] ) {
                compFmt[keyList[i]] = String(Math.floor( secnd / this.compTime[keyList[i]] )).lpad(2 , "0") ;
                secnd = secnd - ( compFmt[keyList[i]] * this.compTime[keyList[i]] );
            }
        }
        this.param.compFmt = compFmt;
        return ( compFmt["Y"] ? ( compFmt["Y"] + "." ) : "" ) +
               ( compFmt["M"] ? ( compFmt["M"] + "." ) : compFmt["Y"] ?  "00." : "" ) +
               ( compFmt["D"] ? ( compFmt["D"] + " " ) : compFmt["Y"] || compFmt["M"] ?  "00 " : "" ) +
               ( compFmt["H"] ? ( compFmt["H"] + ":" ) : "00:" ) +
               ( compFmt["m"] ? ( compFmt["m"] + ":" ) : "00:" ) +
               ( compFmt["s"] ? ( compFmt["s"]       ) : "00"  ) ;
    }
    this.fn_workingRun  = function(){
        if ( this.param.diffTime >= 0 ) {
            var diff = this.param.diffTime  - ( this.param.exeVal *  this.compTime[this.param.exeType] * 1000 );
            if ( diff <= 0 ) {
                this.param.runKey = setInterval(function(){
                    this.param.diffTime   -= this.param.exeIntrvl;
                    this.param.diffFmt     = this.fn_DiffFmt(this.param.diffTime);
                    if ( this.param.diffTime < 0 ) {
                        this.event.onComplete(this.param);
                        clearInterval(this.param.runKey);
                    } else {
                        this.event.onRunCallBack(this.param);
                    }
                }.bind(this), this.param.exeIntrvl);
            } else {
                this.param.diffFmt   = this.fn_DiffFmt(this.param.diffTime);
                this.event.onRunStart(this.param);
                this.param.runKey = setTimeout(function(){
                    this.param.diffTime -= diff;
                    this.param.diffFmt   = this.fn_DiffFmt(this.param.diffTime);
                    this.event.onRunCallBack(this.param);
                    this.fn_workingRun();
                }.bind(this), diff);
            }
            Timers.runKeyList.push(this.param.runKey);
        } else {
            this.event.onComplete(this.param);
        }
    };
}
Timers.runKeyList = [];
Timers.execute = function(options){
    var setting = $.extend({
        runDateTime   : null
       ,sysDateTime   : null
       ,onRunStart    : null
       ,onRunCallBack : null
       ,onComplete    : null
       ,exeVal        : 1
       ,exeType       : "D"
       ,exeIntrvl     : 1000
    },options);
    if ( setting.runDateTime == null) {
        gfn_alertMsgBoxM("날짜 형식이 확인하여 주십시요.<br/> 'yyyy.MM.dd hh:mm:ss'으로 입력하여 주십시요");
        return false;
    }
    var tm = new Timers();
    if ( tm.fn_init(setting) ) {
        gfn_alertMsgBoxM("날짜 형식이 확인하여 주십시요.<br/> 'yyyy.MM.dd hh:mm:ss'으로 입력하여 주십시요");
        return false;
    }
    if ( setting.sysDateTime != null) {
        tm.fn_initRun(setting.sysDateTime);
        tm.fn_workingRun();
    } else {
        $.ajaxMegaBox({
            url     : "/getSystemDate",
            success : function (data, textStatus, jqXHR) {
                tm.fn_initRun(data.sysDate.toDay + " " + data.sysDate.toTime);
                tm.fn_workingRun();
            }
        });
    }
}

/*
Y : 년, M : 월 , D : 일 , H : 시 , m : 분 , s : 초
Timers.call(20,'m',null,function(){
    alert("20분이 되었습니다");
}
*/

Timers.timeStemp = function(onRunCallBack ) {
    var tm = new Timers();
    var param = {};
    var ti    = 1000;
    var diff  = 0;
    param.timeStemp = tm.fn_DiffFmt(0);
    param.runKey = setInterval(function(){
        param.timeStemp = tm.fn_DiffFmt(diff += ti);
        onRunCallBack(param);
    }, ti);
}

Timers.call = function(diffTimeValue , diffTimeType , onRunStart , onRunCallBack ) {
    var tm = new Timers();
    var param = {};
    var ti    = 1000;
    param.time = tm.compTime[diffTimeType] * diffTimeValue;
    if ( onRunStart ) onRunStart(param);
    param.runKey = setTimeout(function(){
        if ( onRunCallBack ) onRunCallBack(param);
    }, param.time * ti);
}

Timers.clearTimer = function(runKey) {
    clearTimeout(runKey);
    return this;
};
Timers.allClearTimer = function() {
    Timers.runKeyList.forEach(function(runKey,i) {
        clearTimeout(runKey);
    });
    return this;
};

$(function() {

    // 접속대기 모달창
    $(window).on('load', function(){
        //$modal('layer_age_alert');
    });

    // 접속대기 모달창 닫기
    $("#layer_age_alert .btn-modal-close").on('click', function() {
        //$modal('layer_age_alert').hide();
    });

    // footer < 극장찾기
    $('#footer .btn-looking-theater').on('click', function(e) {

        e.preventDefault();

        var $div = $('#layer_looking_theater');

        // 값 조회
        $.ajaxMegaBox({
            dataType      : 'html',
            contentType   : 'application/json;charset=UTF-8',
            url           : '/on/oh/ohc/Brch/selectFooterBrchListWithArea.do',
            commAt        : true,
            success       : function (data, textStatus, jqXHR) {

                $div.html(data);
            }
        });
    });

    //header < 좌측상단 영화검색
    $('#header .link-area .header-open-layer.btn-layer-search').on('click', function(e) {

        //if( $("#layer_header_search").hasClass("appendHtml") ) return;

    	$("#layer_header_search").empty();

        //로딩 모달 실행
        //gfn_logdingModal();

        $.ajaxMegaBox({
            url     	: "/on/oh/ohz/Header",
            dataType    : 'html',
            commAt        : true,
            success		: function (data) {
                $("#layer_header_search").append(data);
                $("#layer_header_search").addClass("appendHtml");

                //로딩 모달 종료
                //gfn_logdingModal();
            }
        });
    });

    //header < 우측상단 유저버튼
    $('#header .link-area .header-open-layer.btn-layer-mymega').on('click', function(e) {

        //레이어 닫을경우 리턴
        if( $("#layer_mymega2").hasClass('on') ){
            return;
        }

        //로그인여부 조회 후 유저정보 조회
        selectLoginSession();

    });

    var isLogin = "";

    //로그인여부 조회
    var selectLoginSession = function() {
        $.ajaxMegaBox({
            contentType   : 'application/json;charset=UTF-8',
            url           : '/on/oh/ohg/MbLogin/selectLoginSession.do',
            data          : {},
            success       : function (data, textStatus, jqXHR) {

                //재호출 방지 (로그인 유무사항이 변경됐을 경우만 동작)
                //if( isLogin != "" && isLogin == data.resultMap.result ) {return;}

                isLogin = data.resultMap.result;

                switch ( isLogin ) {
                    case "Y" :
                        $("#layer_mymega2 .wrap .login-after").show();
                        $("#layer_mymega2 .wrap .login-before").hide();
                        // 유저정보 조회
                        setScnBoardInfo();
                        break;
                    default :
                        $("#layer_mymega2 .wrap .login-after").hide();
                        $("#layer_mymega2 .wrap .login-before").show();
                        $("#layer_mymega2 .wrap").show();
                        break;
                }
            },
        });
    }

    // 유저정보 조회
    var setScnBoardInfo = function() {

        // 로딩 모달 실행
        //gfn_logdingModal();

        $.ajaxMegaBox({
            contentType   : 'application/json;charset=UTF-8',
            url           : '/on/oh/ohh/MyScnBoard/selectMyScnBoardInfo.do',
            async		  : true,
            data		  : JSON.stringify({"sellStatCd": "P"}),
            success       : function (data, textStatus, jqXHR) {

                makeMymegaForCustInfo      (data); // 회원정보
                makeMymegaForMembershipInfo(data); // 멤버십 정보생성
                makeMymegaForCouponInfo    (data); // 포인트,쿠폰,관람권
                makeMymegaForBokdList      (data); // 예매 리스트
                makeMymegaForPurcList      (data); // 구매 리스트
                makeMymegaForCponPassInfo  (data); // 쿠폰패스 정보

                $("#layer_mymega2 .wrap").show();


                // 로딩 모달 종료
                //gfn_logdingModal();
            },
            complete		 : function (data, textStatus, jqXHR) {
                if( textStatus.indexOf('error') > -1 ){
                    $("#layer_mymega2 .wrap .login-after").hide();
                    $("#layer_mymega2 .wrap .login-before").show();
                    $("#layer_mymega2 .wrap").show();
                }
            }
        });


    }

    // 유저 정보 생성
    var makeMymegaForCustInfo = function(data){

        //vip정보
        // switch ( data.vipAt ) {
        //     case "Y" 	: $("#layer_mymega2 .vip").text( data.custInfo.mbClassNm ); break;
        //     default		: $("#layer_mymega2 .vip").text( "" ); break;
        // }

        // $("#layer_mymega2 .name").text					( data.custInfo.mbNm );				// 유저명
        //$("#layer_mymega2 .last-date em").text			( data.custInfo.lastLoginDt );		// 마지막 접속일

        $('#layer_mymega2 .name').html(data.custInfo.mbNm +'<span>님</span>');
        $('#layer_mymega2 .mbimg').html('<img src="https://img.megabox.co.kr/static/pc/images/2023/01/member_'+ data.custInfo.mbClassNm +'_2.png" alt="'+ data.custInfo.mbClassNm +'" />');
    }

    // 멤버십 정보 생성
    var makeMymegaForMembershipInfo = function(data){

        var html = "";

        //회원등급 VIP이상일 때 아이콘
        // if( data.vipAt == "Y" ){
        //     switch(data.custInfo.mbClassCd){
        //         case "RVIP":
        //             html += '<i class="iconset ico-header-vipp"></i>';
        //             break;
        //         case "VVIP":
        //             html += '<i class="iconset ico-header-vvip"></i>';
        //             break;
        //         default:
        //             html += '<i class="iconset ico-header-vip"></i>';
        //     }
        // }

        // 가입된 스페셜 멤버쉽 설정
        if( data.mbshipJoinInfo.length > 0 ){

            $.each(data.mbshipJoinInfo, function(i, param) {

                if(param.svcTyCd == 'SMT01') {
                    html += '<li><img src="https://img.megabox.co.kr/static/pc/images/2023/01/logo_so_film.png" alt="filmsociety" /></li>';
                }

                if(param.svcTyCd == 'SMT02') {
                    html += '<li><img src="https://img.megabox.co.kr/static/pc/images/2023/01/logo_so_cla.png" alt="classic society" /></li>';
                }
            });

        }else{
            html += '<li class="txt">가입된 스페셜 멤버십이 없어요!</li>';
        }

        $("#layer_mymega2 .membership").html( html );
    }

    // 포인트,쿠폰,관람권
    var makeMymegaForCouponInfo = function(data){

        // 할인+제휴
        data.cponInfo.cponCnt += data.cponInfo.othcomCponCnt;

        $("#layer_mymega2 .point .count").text( data.pointInfo.totHoldPoint.format() );	// 쿠폰포인트
        $("#layer_mymega2 .coupon .count").html( "<em>" + data.cponInfo.cponCnt + "</em><span>장</span>" ); 				// 할인+제휴
        $("#layer_mymega2 .movieTk .count").html( "<em>" + data.cponInfo.movieMvtchkHoldCnt + "</em><span>장</span>" ); 	// 관람권

    }

    //예매내역
    var makeMymegaForBokdList = function(data){

        // 예매내역 영화명
        switch ( data.bokdList.length ) {
            case 0 		: $("#layer_mymega2 .reserve .count").html( "<div class='txt'>예매내역이 없어요!</div>" ); break;
            default		: $("#layer_mymega2 .reserve .count").html( "<em>"+data.bokdList.length+"</em><span>건</span>" ); break;
        }

        //$("#layer_mymega2 .reserve .btn-fixed em").text	( data.bokdList.length );				// 예매내역 건수
    }

    //구매내역
    var makeMymegaForPurcList = function(data){

        $("#layer_mymega2 .buy .count em").text			( data.pureInfo.length );				// 구매건수

    }

    // 쿠폰패스
    var makeMymegaForCponPassInfo = function(data) {
        if (data.cponPassList.length > 0) {
            $('#layer_mymega2 .couponpass').show();
        }
    }


    var pushParamData = {
            recordCountPerPage: 5,
            currentPage: 1,
            totalPage: 0,
            readAt:'N'
    };

    //알림함
    $(document).on('click', '.after .notice', function(){
        if( $('.right-link .after .layer-header-notice').is(".on") == false ){
            makeMbNoticeList('');
        }
    });

    //알림함 더보기
    $(document).on('click', '.notice-list-more button', function(){
        makeMbNoticeList('PAGE');
    });

    var makeMbNoticeListCnt = function(){

        pushParamData.readAt = 'N';

        $.ajax({
            contentType   : 'application/json;charset=UTF-8',
            url           : '/on/oh/ohz/MySetting/selectMbPushHistCnt.do',
            type          : 'POST',
            data          : JSON.stringify(pushParamData),
            success       : function (data, textStatus, jqXHR) {
                if( data.totalCnt == undefined ){
                    $(".right-link .after .notice").hide();
                }
                if( data.totalCnt > 0 ){
                    $(".right-link .after .notice").addClass("on");
                }
            }
        });
    }

    //알림함 새글 조회
    // 수정 김진규
    // 5개 메뉴에 들어올때만
	var path = location.pathname;
    var mainChkPath = ['/main', '/store', '/booking', '/event', '/myMegabox'];
    if(mainChkPath.indexOf(path) != -1){
      makeMbNoticeListCnt();
    }

    var makeMbNoticeList = function(flag){

        if(flag == 'PAGE') {
            if(pushParamData.currentPage < pushParamData.totalPage) {
                pushParamData.currentPage++;
            }else {
                gfn_alertMsgBox("알림함 내역이 없습니다.");
                return;
            }
        }

        pushParamData.readAt='';

        $.ajaxMegaBox({
            contentType   : 'application/json;charset=UTF-8',
            url           : '/on/oh/ohz/MySetting/selectMbPushHist.do',
            data          : JSON.stringify(pushParamData),
            success       : function (data, textStatus, jqXHR) {

                var target = $(".layer-header-notice .notice-wrap");

                if(data.mbNoticeList != undefined && data.mbNoticeList.length > 0) {

                    //총 페이지 셋팅
                    pushParamData.totalPage = data.pageCnt;

                    //초기화
                    if( pushParamData.currentPage == 1 ){
                        target.find(".list").html("");
                    }

                    var list = "";

                    for(var i in data.mbNoticeList) {
                        var rowData = data.mbNoticeList[i];

                        rowData.notiLinkUrl = rowData.notiLinkUrl.replace("/movie/online-review?","/movie-detail?");

                        if(rowData.notiLinkUrl.split("/")[1] == "mobile-order" || rowData.notiLinkUrl.split("?")[0] == "/order"){
                        	rowData.notiLinkUrl = "javascript:alert('모바일앱 전용 링크입니다.')";
                        }

                        list =
                            '<li>'
                            //+'	<p class="tit"><a href="' + rowData.notiLinkUrl + '" title="' + rowData.notiTitle + '">' + rowData.notiTitle + '</a></p>'
                            +'	<p class="tit">' + rowData.notiTitle + '</p>'
                            +'	<div class="cont">'
                            +		'<a href="' + rowData.notiLinkUrl + '" title="' + rowData.notiTitle + '">'+rowData.notiCn+'</a>'
                            +'	</div>'
                            +'	<p class="time">' + rowData.fstRegDt + '</p>'
                            +'</li>';
                            target.find(".list").append(list);
                    }

                    target.find(".totalCnt").text(data.totalCnt); //총건수
                    $(".notice-list-more").show();
                }else {
                    list =
                            '<li class="no-list">'
                            +'	알림 내역이 없습니다.'
                            +'</li>';

                    target.find(".list").html(list);
                    target.find(".totalCnt").text(0); //총건수
                    $(".notice-list-more").hide();
                }
            }
        });
    }

    //하단 모바일 화면 전환
    $(document).on('click', 'div.go-mobile a', function(){

        var returnPath = "";

        if( location.pathname.indexOf("/event") > -1 ||
            location.pathname.indexOf("/store") > -1 ||
            location.pathname.indexOf("/movie") > -1
                ){
            returnPath = location.pathname;
        }

        $.ajaxMegaBox({
            url      : "/getToken",
            async    : true,
            success  : function (data, textStatus, jqXHR) {
            },
            error    : function (data, textStatus, jqXHR) {
            },
            complete : function (data, textStatus, jqXHR) {
                gfn_setCookie("FROM_MOBILE_WEB", "N", 30, location.host.substr(location.host.indexOf(".")));
                location.href = $('div.go-mobile a').data("url") + "/sessionCpResponse?returnPath="+ returnPath + location.search + "&token="+ encodeURIComponent(data.responseJSON.token) ;
            }
        });
    });

    // 이벤트 상세 버튼 클릭
    $('.container').on('click','.eventBtn', function(e) {
        e.preventDefault();
        var form = MegaboxUtil.Form.createForm();
        form.append('<input type="hidden" name="eventNo" value="' + $(this).data('no') + '">');
        form.attr('action', '/event/detail');
        form.attr('method', 'get');
        form.submit();
    });

    //패스워드 공백 제거
    $(document).on('focus','input:password', function(e) {
    	$('input:password').passTrim();
    });

    //class 선언 공백제거
    $(document).on('focus','.strTrim', function(e) {
    	$('.strTrim').passTrim();
    });
});

/**
 * 좌측상단 > 사이트맵 > 나의메가박스 비로그인시 처리
 * @param url
 * @returns
 */
function movePage(url, msg){
    gfn_confirmMsgBox(msg, function(){
        fn_viewLoginPopup('default','pc');
    });
}

//쿠키설정
function gfn_setCookie(cname, cvalue, exdays, domain) {
    var d = new Date();
    d.setTime(d.getTime() + (exdays*24*60*60*1000));
    var expires = "expires="+d.toUTCString();
    domain = domain ? '; domain=' + domain : '';
    document.cookie = cname + "=" + cvalue + "; " + expires + ";path=/" + domain;
    //console.log( cname + "=" + cvalue + "; " + expires + ";path=/" + domain );
}

/**
 * 온라인채널 이용내역 집계를 위해 사용한다.
 * 페이지 별 URL 분기가 어려울 경우, 집계용 URL을 따로 호출하기 위해 사용한다.
 *
 * @param {string} lastUrl: URL 구분자
 */
function fn_urlTrack(lastUrl) {
    var pathName = window.location.pathname;
    $.ajax({
        url: '/urlTrack' + pathName + lastUrl,
        success: function (data) {
        }
    });
}