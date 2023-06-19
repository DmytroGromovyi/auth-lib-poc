package com.poc.authlib.common.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public final class AuthSystemUserDTO {
    private String userId;
    private String[] roles;
}
