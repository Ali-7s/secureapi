package dev.ali.secureapi.repository;


import dev.ali.secureapi.model.Post;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.util.List;


@Repository
public class PostRepository {
    private final JdbcClient jdbc;

    public PostRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }


    public List<Post> findAll(int page, int size) {
        int offset = page *size;
        String sql = "SELECT * FROM posts ORDER BY created_at DESC LIMIT :limit OFFSET :offset";


        return jdbc.sql(sql)
                .param("limit", size)
                .param("offset", offset)
                .query(Post.class) // Auto-maps 'user_id' column to 'userId' field
                .list();    }


    public Post findById(Long id) {
        String sql = "SELECT * FROM posts WHERE id = :id";
        return jdbc.sql(sql).param("id", id).query(Post.class).single();
    }

    public List<Post> findByUserId(Long userId) {
        String sql = "SELECT * FROM posts WHERE user_id = :userId";
        return jdbc.sql(sql).param("userId", userId).query(Post.class).list();
    }
}
