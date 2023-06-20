package com.poc.authlib.common.supply;

import com.poc.authlib.common.dto.AuthSystemUserDTO;
import com.poc.authlib.common.dto.RoleDTO;

import java.util.Collections;
import java.util.function.Supplier;
import javax.validation.constraints.NotNull;

public interface AuthorizedUserSupplier extends Supplier<AuthSystemUserDTO> {

    default @NotNull AuthSystemUserDTO get() {
        //return mocked user by default if security is turned off
        return AuthSystemUserDTO.builder()
                .userId("user012")
                .roles(Collections.singletonList(RoleDTO.builder()
                        .name("USER_ROLE")
                        .permissions(Collections.singletonList("Request.READ"))
                        .build()))
                .build();
    }

}
