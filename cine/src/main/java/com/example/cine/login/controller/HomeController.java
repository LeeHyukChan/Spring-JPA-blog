package com.example.cine.login.controller;

import java.util.HashMap;
import java.util.UUID;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;

import com.example.cine.login.entity.KakaoProfile;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpSession;

@Controller
public class HomeController {

	KakaoAPI kakaoApi = new KakaoAPI();

	@GetMapping("/auth/kakao/callback")
	public @ResponseBody String kakaoCallback(@RequestParam("code") String str) {

		// post방식으로 key=value 데이터를 요청(카카오쪽으로)
		// Retrofit2
		// okHttp
		// RestTemplate

		RestTemplate rt = new RestTemplate();

		// HttpHeader 오브젝트 생성
		HttpHeaders header = new HttpHeaders();
		header.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");

		// HttpBody 오브젝트 생성
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "authorization_code");
		params.add("client_id", "d71369d0800a2ee977fca54cda41a9dd");
		params.add("redirect_uri", "http://localhost:8081/auth/kakao/callback");
		params.add("code", str);

		// httpHeader와 HttpBody를 하나의 오브젝트에 담기
		HttpEntity<MultiValueMap<String, String>> kakaoTokenRequest = new HttpEntity<>(params, header);

		// Http요청하기 - post방식으로 그리고 response 변수의 응답 받음
		ResponseEntity<String> response = rt.exchange("https://kauth.kakao.com/oauth/token", HttpMethod.POST,
				kakaoTokenRequest, String.class);

		// Gson,Json,Simple, ObjectMapper
		ObjectMapper objectMapper = new ObjectMapper();
		OAuthToken oauthToken = null;
		try {
			oauthToken = objectMapper.readValue(response.getBody(), OAuthToken.class);
		} catch (JsonMappingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("카카오 토큰" + oauthToken.getAccess_token());

		RestTemplate rt2 = new RestTemplate();

		// HttpHeader 오브젝트 생성
		HttpHeaders header2 = new HttpHeaders();
		header2.add("Authorization","Bearer "+oauthToken.getAccess_token());
		header2.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");


		// httpHeader와 HttpBody를 하나의 오브젝트에 담기
		HttpEntity<MultiValueMap<String, String>> kakaoProfileRequest2 = new HttpEntity<>(header2);

		// Http요청하기 - post방식으로 그리고 response 변수의 응답 받음
		ResponseEntity<String> response2 = rt2.exchange(
				"https://kapi.kakao.com/v2/user/me", 
				HttpMethod.POST,
				kakaoProfileRequest2, 
				String.class);
		ObjectMapper objectMapper2 = new ObjectMapper();
		KakaoProfile kakaoProfile = null;
		try {
			kakaoProfile = objectMapper2.readValue(response2.getBody(), KakaoProfile.class);
		} catch (JsonMappingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//필요한 MemberEntity필드 username,password,email
		System.out.println("카카오 아이디(번호)"+kakaoProfile.getId());
		System.out.println("카카오 아이디(이메일)"+ kakaoProfile.getKakao_account().getEmail());
		
		System.out.println("프로젝트 유저네임:" + kakaoProfile.getKakao_account().getEmail()+"_"+kakaoProfile.getId());
		System.out.println("프로젝트 이메일:" + kakaoProfile.getKakao_account().getEmail());
		UUID garbagePassword = UUID.randomUUID();
		System.out.println("프로젝트 패스워드 :" + garbagePassword);
		System.out.println();
		
		return response2.getBody();
	}

	@RequestMapping(value = "/login")
	public ModelAndView login(@RequestParam("code") String code, HttpSession session) {
		ModelAndView mav = new ModelAndView();
		// 1번 인증코드 요청 전달
		String access_token = kakaoApi.getAccessToken(code);
		// 2번 인증코드로 토큰 전달
		HashMap<String, Object> userInfo = kakaoApi.getUserInfo(access_token);

		System.out.println("login info : 확인 " + userInfo.toString());

		if (userInfo.get("kakaoemail") != null) {
			session.setAttribute("kakaoemail", userInfo.get("kakaoemail"));
			session.setAttribute("access_token", access_token);
			session.setAttribute("kakaoname", userInfo.get("kakaoname"));
		}

		mav.addObject("kakaoemail", userInfo.get("kakaoemail"));
		mav.addObject("kakaoname", userInfo.get("kakaoname"));
		mav.setViewName("/main/cinemain");
		return mav;
	}
// 카카오 로그인 구현

	@RequestMapping(value = "/logout")
	public ModelAndView logout(HttpSession session) {
		ModelAndView mav = new ModelAndView();
		kakaoApi.kakaoLogout((String) session.getAttribute("accessToken"));
		session.removeAttribute("accessToken");
		session.removeAttribute("userid");
		mav.setViewName("/main/cinemain");
		return mav;
	}

	@GetMapping("modal")
	public String modal() {
		return "modal";
	}
}
