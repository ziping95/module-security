package com.wzp.module.security.handler;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.wzp.module.core.utils.RedisUtil;
import com.wzp.module.security.SecurityConstant;
import com.wzp.module.security.dto.UserDto;
import com.wzp.module.user.UserConstant;
import com.wzp.module.user.bean.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * 认证成功处理类
 */
@Component
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    /**
     * Called when a user has been successfully authenticated.
     *
     * @param request        the request which caused the successful authentication
     * @param response       the response
     * @param authentication the <tt>Authentication</tt> object which was created during
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String token = UUID.randomUUID().toString().replaceAll("-","");
        // 直接序列化UserDetails对象,在反序列化时由于isEnabled方法引起反序列化失败,因为序列化时默认属性名为enabled,但由于实现的UserDetails接口因此无enabled属性,导致报错
        RedisUtil.put(UserConstant.TOKEN_REDIS_KEY + token, UserDto.userDtoToUser((UserDto) authentication.getPrincipal()), SecurityConstant.EXPIRES);
        Cookie cookie = new Cookie("token",token);
        cookie.setPath("/");
        cookie.setMaxAge(SecurityConstant.EXPIRES.intValue());
        response.addCookie(cookie);
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_OK);
        Map<String,Object> info = new HashMap<>();
        info.put("code",200);
        info.put("msg","登陆成功");
        info.put("token",token);
        PrintWriter out = response.getWriter();
        out.write(JSONObject.toJSONString(info));
        out.flush();
        out.close();
    }
}
