package com.wzp.module.security.dto;

import com.wzp.module.user.bean.Role;
import com.wzp.module.user.bean.User;
import jdk.nashorn.internal.runtime.FindProperty;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * 除了isEnabled 方法实现了逻辑,其他方法统一返回true,暂时用不到
 */
@EqualsAndHashCode(callSuper = true)
@Data
public class UserDto extends User implements UserDetails {

    private boolean enabled;
    private boolean credentialsNonExpired;
    private boolean accountNonLocked;
//    private boolean accountNonExpired;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(getRole().getName()));
        return authorities;
    }

    @Override
    public String getUsername() {
        return getLoginId();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 账号是否有效,1 代表有效
     * @return
     */
    @Override
    public boolean isEnabled() {
        return "1".equals(getStatus());
    }

    public static UserDto initBean (User user) {
        UserDto userDto = new UserDto();
        userDto.setId(user.getId());
        userDto.setLoginId(user.getLoginId());
        userDto.setCreateDate(user.getCreateDate());
        userDto.setUpdateDate(user.getUpdateDate());
        userDto.setEmail(user.getEmail());
        userDto.setGender(user.getGender());
        userDto.setIp(user.getIp());
        userDto.setLastLoginDate(user.getLastLoginDate());
        userDto.setMobilePhone(user.getMobilePhone());
        userDto.setNickName(user.getNickName());
        userDto.setTrueName(user.getTrueName());
        userDto.setPassword(user.getPassword());
        userDto.setRole(user.getRole());
        userDto.setStatus(user.getStatus());
        return userDto;
    }

    public static User userDtoToUser (UserDto userDto) {
        User user = new User();
        user.setId(userDto.getId());
        user.setLoginId(userDto.getLoginId());
        user.setCreateDate(userDto.getCreateDate());
        user.setUpdateDate(userDto.getUpdateDate());
        user.setEmail(userDto.getEmail());
        user.setGender(userDto.getGender());
        user.setIp(userDto.getIp());
        user.setLastLoginDate(userDto.getLastLoginDate());
        user.setMobilePhone(userDto.getMobilePhone());
        user.setNickName(userDto.getNickName());
        user.setTrueName(userDto.getTrueName());
        user.setPassword(userDto.getPassword());
        user.setRole(userDto.getRole());
        user.setStatus(userDto.getStatus());
        return user;
    }
}
