package com.example.cine.login.controller;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<String> handleDataIntegrityViolationException(DataIntegrityViolationException ex) {
        // 무결성 제약 조건 위반 시 사용자에게 전달할 메시지 설정
        String errorMessage = "아이디 중복체크 결과를 변경하지 말아주세요";
        return new ResponseEntity<>(errorMessage, HttpStatus.BAD_REQUEST);
    }
}