package com.wzp.module.security.config;

import com.wzp.module.security.handler.LoginFailureHandler;
import com.wzp.module.security.handler.LoginSuccessHandler;
import com.wzp.module.security.handler.MyAccessDeniedHandler;
import com.wzp.module.security.handler.MyAuthenticationEntryPoint;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

import javax.annotation.Resource;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private UserDetailsService userDetailsService;
    @Resource
    private UrlAccessDecisionManager urlAccessDecisionManager;
    @Resource
    private UrlFilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource;
    @Resource
    private MyAccessDeniedHandler myAccessDeniedHandler;
    @Resource
    private MyAuthenticationEntryPoint myAuthenticationEntryPoint;
    @Resource
    private LoginSuccessHandler loginSuccessHandler;
    @Resource
    private LoginFailureHandler loginFailureHandler;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 指定自定义业务实现类和密码加密类
        auth.userDetailsService(userDetailsService).passwordEncoder(new MyPasswordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 登陆相关的配置
        http.formLogin().usernameParameter("loginId").passwordParameter("password").loginProcessingUrl("/open/login")
                .successHandler(loginSuccessHandler).failureHandler(loginFailureHandler);

        http.authorizeRequests().antMatchers(HttpMethod.OPTIONS).permitAll()
                // 这里只放开open路径,其他路径可去白名单配置
                .antMatchers("/open/**").permitAll()
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O o) {
                        // 因为在容器初始化时就已经把数据库权限相关的信息放入内存中,因此不需要InvocationSecurityMetadataSource中获取
//                        o.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource);
                        o.setAccessDecisionManager(urlAccessDecisionManager);
                        return o;
                    }
                })
                .anyRequest().authenticated();




        http.csrf().disable();

        // 异常处理
        http.exceptionHandling()
                .accessDeniedHandler(myAccessDeniedHandler)
                .authenticationEntryPoint(myAuthenticationEntryPoint);
    }

}
