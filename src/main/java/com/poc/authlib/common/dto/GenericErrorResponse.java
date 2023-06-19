package com.poc.authlib.common.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class GenericErrorResponse {
    private String errorMessage;
    private int errorCode;
}
