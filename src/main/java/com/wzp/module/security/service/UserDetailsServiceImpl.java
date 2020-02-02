package com.wzp.module.security.service;

import com.wzp.module.security.dto.UserDto;
import com.wzp.module.user.bean.Role;
import com.wzp.module.user.bean.User;
import com.wzp.module.user.mapper.UserMapper;
import com.wzp.module.user.service.UserService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;

@Component("userDetailsService")
public class UserDetailsServiceImpl implements UserDetailsService {

    @Resource
    private UserService userService;

    @Override
    public UserDetails loadUserByUsername(String loginId) throws UsernameNotFoundException {
        User user = userService.selectUserByLoginId(loginId);
        if (user == null) {
            throw new UsernameNotFoundException("用户不存在");
        }
        return UserDto.initBean(user);
    }
}
