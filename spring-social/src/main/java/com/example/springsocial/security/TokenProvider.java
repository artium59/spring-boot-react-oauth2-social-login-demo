package com.example.springsocial.security;

import com.example.springsocial.config.AppProperties;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Date;

/*
  header와 payload는 base64로 인코딩만 되므로 누구나 디코딩하여 확인할 수 있다.
  따라서 payload에는 중요한 정보가 포함되면 안된다. 하지만 verify signature는 SECRET KEY를 알지 못하면 복호화할 수 없다.

  https://brownbears.tistory.com/440
*/

@Service
public class TokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    private AppProperties appProperties;

    public TokenProvider(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    public String createToken(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + appProperties.getAuth().getTokenExpirationMsec());

        return Jwts.builder()
                // sub: 사용자 고유 번호
                .setSubject(Long.toString(userPrincipal.getId()))
                // iat: JWT 발급 시간
                .setIssuedAt(new Date())
                // exp: JWT 만료 시간
                .setExpiration(expiryDate)
                // PAYLOAD에 email data 추가
                .claim("email", userPrincipal.getEmail())
                // VERIFY SIGNATURE: HMACSHA512방식으로 your-256-bit-secret을 통해 암호화
                .signWith(SignatureAlgorithm.HS512, appProperties.getAuth().getTokenSecret())
                .compact();
    }

    public String getUidFromJwtToken(String token) {
        // parseClaimsJws(token): token을 Jws로 파싱
        // getBody(): token에 저장했던 data들이 담긴 claims return (PAYLOAD) (getHead(), getBody(), getSignature())
        // getSubject(): return PAYLOAD의 sub
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public String getEmailFromJwtToken(String token) {
        // get("email", String.class): return PAYLOAD의 email
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().get("email", String.class);
    }

    public boolean validateToken(String authToken) {
        try {
            // application.yml의 tokenSecret으로 복호화
            // 성공하면 true, 아님 에러 or false
            Jwts.parser().setSigningKey(appProperties.getAuth().getTokenSecret()).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException ex) {
            logger.error("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            logger.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            logger.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            logger.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string is empty.");
        }
        return false;
    }

}
