package dev.ali.secureapi.dto;

import dev.ali.secureapi.model.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserSummaryDTO {
    private Long id;
    private String username;
    private String displayName;

    public UserSummaryDTO(User user) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.displayName = user.getDisplayName();
    }
}

