package com.wzp.module.security.config;

import com.alibaba.fastjson.JSONObject;
import com.wzp.module.core.utils.CollectionUtil;
import com.wzp.module.core.utils.RedisUtil;
import com.wzp.module.security.SecurityConstant;
import com.wzp.module.user.bean.User;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.servlet.http.Cookie;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;

@Component
public class UrlAccessDecisionManager implements AccessDecisionManager {

    private static Logger logger = LoggerFactory.getLogger(UrlAccessDecisionManager.class);

    private static final Method getAuthorizeExpression = initReflect();

    /**
     * 将角色和权限保存在内存中
     */
    private static final Map<String,Object> roleAndPaths = new HashMap<>();


    @Override
    public void decide(Authentication authentication, Object o, Collection<ConfigAttribute> collection) throws AccessDeniedException, InsufficientAuthenticationException {
        String requestUrl = ((FilterInvocation) o).getRequestUrl();
        Cookie[] cookies = ((FilterInvocation) o).getRequest().getCookies();

        // 这里是为了兼容WebSecurityConfig中的路径配置
        List<ConfigAttribute> configPath = new ArrayList<>(collection);
        try {
            if (getAuthorizeExpression != null) {
                String expression = getAuthorizeExpression.invoke(configPath.get(0)).toString();
                if(SecurityConstant.PERMITALL.equals(expression)) {
                    return;
                }
            } else {
                logger.error("反射获取getAuthorizeExpression方法对象为空");
            }
        } catch (IllegalAccessException | InvocationTargetException e) {
            e.printStackTrace();
            logger.error("反射获取security配置失败,异常为{}",e.getMessage());
        }

        // 先验证是否为游客接口,符合条件则直接放行
        if(isPathMatcher(SecurityConstant.ANYONE,requestUrl)) {
            return;
        }

        // 从缓存中拿到token,作为key去redis查询是否有当前这个用户
        if(cookies != null && cookies.length != 0) {
            for (Cookie c : cookies) {
                if("token".equals(c.getName())) {
                    String token = c.getValue();
                    User user = (User) RedisUtil.get(SecurityConstant.TOKEN_REDIS_KEY + token);
                    SecurityContextHolder.getContext().getAuthentication();
                    // 验证token是否正确
                    if (user != null && user.getRole() != null && isPathMatcher(user.getRole().getId(),requestUrl)) {
                        return;
                    }
                    throw new AccessDeniedException("权限不足");
                }
            }
        }
        throw new BadCredentialsException("用户未登录");
    }

    @Override
    public boolean supports(ConfigAttribute configAttribute) {
        return false;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return false;
    }

    /**
     * 匹配路径
     * @param roleId
     * @param requestUrl
     * @return
     */
    private boolean isPathMatcher (String roleId,String requestUrl) {
        List<String> pathList = (List<String>) RedisUtil.hashGet(SecurityConstant.ROLE_REDIS_KEY,roleId);
        AntPathMatcher antPathMatcher = new AntPathMatcher();
        if(CollectionUtil.isNotEmpty(pathList)) {
            for (String path : pathList) {
                if(antPathMatcher.match(path,requestUrl)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static Map<String, Object> getRoleAndPaths() {
        return roleAndPaths;
    }

    private static Method initReflect() {
        try {
            Class<?> clazz = Class.forName("org.springframework.security.web.access.expression.WebExpressionConfigAttribute");
            Method method = clazz.getDeclaredMethod("toString");
            method.setAccessible(true);
            return method;
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            e.printStackTrace();
            return null;
        }
    }
}
