package com.poc.authlib.properties;

import com.poc.authlib.common.enums.Role;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import javax.validation.constraints.NotNull;

@Data
@Validated
@ConfigurationProperties(prefix = "api.permissions")
public class ApiPermissionProperties {
    @NotNull
    private List<String> whitelistedEndpoints = new ArrayList<>();
    @NotNull
    private final Map<Role, List<String>> permissionMap = new TreeMap<>();
}

