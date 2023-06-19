package com.poc.authlib.common.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum Role implements Comparable<Role> {
    CUSTOM("CUSTOM_ROLE"),
    ADMIN("ADMIN_ROLE"),
    USER("USER_ROLE");

    @Getter
    private final String roleName;
}
