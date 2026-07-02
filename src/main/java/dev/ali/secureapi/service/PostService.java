package dev.ali.secureapi.service;

import dev.ali.secureapi.model.Post;
import dev.ali.secureapi.repository.PostRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class PostService {
    private final PostRepository postRepository;

    public Post findById(Long id){
        return postRepository.findById(id);
    }

    public List<Post> findAll(int page, int size){
        return postRepository.findAll(page, size);
    }

    public void deletePost(Long id, String email){
        //
        log.info("Delete post with id {} and email {}", id, email);
    }


}