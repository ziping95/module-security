package com.wzp.module.security.config;


import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * FilterInvocationSecurityMetadataSource有一个默认的实现类DefaultFilterInvocationSecurityMetadataSource,
 * 该类的主要功能就是通过当前的请求地址，获取该地址需要的用户角色,这里重新定义一个实现类,实现相同的功能
 */
@Component("urlFilterInvocationSecurityMetadataSource")
public class UrlFilterInvocationSecurityMetadataSource extends DefaultFilterInvocationSecurityMetadataSource {


    private final Map<RequestMatcher, Collection<ConfigAttribute>> requestMap;

    /**
     * Sets the internal request map from the supplied map. The key elements should be of
     * type {@link RequestMatcher}, which. The path stored in the key will depend on the
     * type of the supplied UrlMatcher.
     *
     * @param requestMap order-preserving map of request definitions to attribute lists
     */
    public UrlFilterInvocationSecurityMetadataSource(LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap) {
        super(requestMap);
        this.requestMap = requestMap;
    }

    /**=
     * 该方法返回当前用户所拥有的一些属性,该方法可灵活使用,可以返回你想要的一切,如果返回空,则不需要登录直接访问资源
     * 具体逻辑看FilterSecurityInterceptor类的InterceptorStatusToken方法源码(该方法是spring security核心逻辑)
     */
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        return null;
    }

    /**
     * If available, returns all of the {@code ConfigAttribute}s defined by the
     * implementing class.
     * <p>
     * This is used by the {@link AbstractSecurityInterceptor} to perform startup time
     * validation of each {@code ConfigAttribute} configured against it.
     *
     * @return the {@code ConfigAttribute}s or {@code null} if unsupported
     */
    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    /**
     * Indicates whether the {@code SecurityMetadataSource} implementation is able to
     * provide {@code ConfigAttribute}s for the indicated secure object type.
     *
     * @param clazz the class that is being queried
     * @return true if the implementation can process the indicated class
     */
    @Override
    public boolean supports(Class<?> clazz) {
        // todo：暂时还不知道该方法作用
        return FilterInvocation.class.isAssignableFrom(clazz);
    }
}
