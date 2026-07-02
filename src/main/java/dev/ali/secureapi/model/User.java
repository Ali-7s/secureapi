package dev.ali.secureapi.model;

import dev.ali.secureapi.enums.Role;
import lombok.*;

import java.util.Date;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class User {

    private Long id;

    private String username;

    private Role role;

    private String displayName;

    private String password;

    private String email;

    private Date createdAt;


}