package com.alonge.shirodemo.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * @author wuyanlong
 * @desc JWT 工具类
 */
public class JwtUtil {

    /**
     * 签名加密密钥，保存在服务端，是随意定义的
     */
    public static String SECRET = "SDFEEdfdeFDRE";


    public static String createToken(String username) {
        //签发时间
        Date istDate = new Date();

        //设置过期时间
        Calendar nowTime = Calendar.getInstance();
        // token有效时间为5分钟
        nowTime.add(Calendar.MINUTE, 5);
        Date expiresDate = nowTime.getTime();

        Map<String, Object> map = new HashMap<>();
        map.put("alg", "HS256");
        map.put("typ", "JWT");

        String token = "";
        try {
             token = JWT.create()
                    .withHeader(map)
                    .withClaim("username", username)
                    .withExpiresAt(expiresDate)
                    .withIssuedAt(istDate)
                    .sign(Algorithm.HMAC256(SECRET));
        }catch (Exception e) {
            return token;
        }
        return token;
    }


    public static Map<String, Claim> verifyToken(String token) throws SignatureVerificationException{
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SECRET)).build();
        DecodedJWT jwt = null;
        jwt = verifier.verify(token);
        return jwt.getClaims();
    }

    public static String getUsername(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim("username").asString();
        } catch (JWTDecodeException e) {
            return null;
        }
    }

    public static void main(String[] args) {
        //System.out.println(createToken("wuyanl"));
        verifyToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDgzMjA1MjgsImlhdCI6MTU0ODMyMDIyOCwidXNlcm5hbWUiOiJ3dXlhbmwifQ.ddsd-DNrXNSz9j_PPSqyv2Q0");
    }
}
