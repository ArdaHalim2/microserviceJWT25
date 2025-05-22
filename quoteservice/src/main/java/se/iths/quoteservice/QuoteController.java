package se.iths.quoteservice;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Random;

@RestController
@RequestMapping("/api/quotes")
public class QuoteController {

    private final List<String> quotes = List.of(
            "Its only when the map changes that people care about the old one.",
            "They spectate, but only when youre winning.",
            "Maturity is when you realise, even the winners are dragged back to the lobby.",
            "Don’t treat her like a gold scar if she treats you like a gray pistol.",
            "If she was never there with you in the storm, why bring her to the final circle?",
            "To heal, you got to take some damage first.",
            "The smaller the circle, the better the players",
            "You dont get mats by breaking others builds"
    );

    @GetMapping
    public List<String> getQuotes() {
        return quotes;
    }

    @GetMapping("/random")
    public String getRandomQuote() {
        Random random = new Random();
        return quotes.get(random.nextInt(quotes.size()));
    }
}
