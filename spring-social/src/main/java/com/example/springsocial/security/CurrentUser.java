package com.example.springsocial.security;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import java.lang.annotation.*;

/*
  Target: 어노테이션이 적용할 위치

  ElementType.PACKAGE         패키지 선언시
  ElementType.TYPE            타입 선언시
  ElementType.CONSTRUCTOR     생성자 선언시
  ElementType.FIELD           멤버 변수 선언시
  ElementType.METHOD          메소드 선언시
  ElementType.ANNOTATION_TYPE 어노테이션 타입 선언시
  ElementType.LOCAL_VARIABLE  지역 변수 선언시
  ElementType.PARAMETER       매개 변수 선언시
  ElementType.TYPE_PARAMETER  매개 변수 타입 선언시
  ElementType.TYPE_USE        타입 사용시
*/
@Target({ElementType.PARAMETER, ElementType.TYPE})

/*
  Retention: 어떤 시점까지 어노테이션이 영향을 미치는지 결정

  RetentionPolicy.SOURCE  주석은 컴파일 이후에 폐기. 즉 클래스에는 포함이 안된다.
                          소스상에서만 어노테이션 정보를 유지한다. 소스 코드를 분석할 때만 의미가 있으며 바이트 코드 파일에는 정보가 남지 않는다.
  RetentionPolicy.CLASS   (default) 주석은 컴파일러가 클래스를 참조할 때까지(클래스 파일에 기록할 때까지), 런타임때 폐기
                          바이트 코드 파일까지 어노테이션 정보를 유지한다. 하지만 리플렉션을 이용해서 어노테이션 정보를 얻을 수는 없다.
  RetentionPolicy.RUNTIME 컴파일 이후에도 JVM에 의해 참조 가능
                          바이트 코드 파일까지 어노테이션 정보를 유지하면서 리플렉션을 이용해서 런타임시에 어노테이션 정보를 얻을 수 있다.
  https://yookeun.github.io/java/2017/01/13/java-annotation/
*/
@Retention(RetentionPolicy.RUNTIME)

// 문서에도 어노테이션의 정보가 표현
@Documented

// ??
@AuthenticationPrincipal
public @interface CurrentUser {

}
