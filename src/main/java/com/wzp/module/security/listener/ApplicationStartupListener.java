package com.wzp.module.security.listener;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.wzp.module.core.utils.FileUtil;
import com.wzp.module.core.utils.RedisUtil;
import com.wzp.module.security.SecurityConstant;
import com.wzp.module.security.config.UrlAccessDecisionManager;
import com.wzp.module.user.bean.Role;
import com.wzp.module.user.mapper.RoleMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
public class ApplicationStartupListener implements ApplicationListener<ContextRefreshedEvent> {

    @Resource
    private RoleMapper roleMapper;

    /**
     * 在spring容器初始化后将角色和权限对应关系存在内存中
     * @param contextRefreshedEvent
     */
    @Override
    public void onApplicationEvent(ContextRefreshedEvent contextRefreshedEvent) {
        List<Role> roleList = this.roleMapper.findAllRole();
        List<String> whiteList = new ArrayList<>();
        try {
            JSONArray jsonArray = FileUtil.readJsonFile(FileUtil.getWEBINFPath() + "/classes/whiteList.json",JSONArray.class);
            List<JSONObject> temp = jsonArray.toJavaList(JSONObject.class);
            temp.forEach(jsonObject -> {
                whiteList.add(jsonObject.get("path").toString());
            });
        } catch (Exception e) {
            e.printStackTrace();
            log.error("--------------读取白名单出错--------------");
        }
        Map<String,Object> roleAndPaths = new HashMap<>();
        roleAndPaths.put(SecurityConstant.ANYONE,whiteList);
        roleList.forEach(role -> {
            List<String> pathList = new ArrayList<>();
            role.getPermissionList().forEach(permission -> pathList.add(permission.getPath()));
            roleAndPaths.put(role.getId(),pathList);
        });
        UrlAccessDecisionManager.getRoleAndPaths().putAll(roleAndPaths);
    }
}
