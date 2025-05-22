package se.iths.jokeservice;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Random;

@RestController
@RequestMapping("/api/jokes")
public class JokeController {

    private final List<String> jokes = List.of(
            "Why don't programmers like nature? It has too many bugs.",
            "How many programmers does it take to change a light bulb? None, it's a hardware problem.",
            "There are only 10 types of people in the world: those who understand binary, and those who don't."
    );

    @GetMapping
    public List<String> getJokes() {
        return jokes;
    }

    @GetMapping("/random")
    public String getRandomJoke() {
        Random random = new Random();
        return jokes.get(random.nextInt(jokes.size()));
    }
}