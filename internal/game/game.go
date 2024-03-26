package game

import (
	"fmt"
	"math/rand"
)

// Game state
type Game struct {
	PlayerA Player
	PlayerB Player
	round   int
	End     bool
	Deck    Deck
}

// Player hand
type Player struct {
	Points int
	Cards  []Card
}

type Suit string

const (
	Hearts   Suit = "Hearts"
	Diamonds      = "Diamonds"
	Clubs         = "Clubs"
	Spades        = "Spades"
)

type Rank string

const (
	Ace   Rank = "Ace"
	Two        = "2"
	Three      = "3"
	Four       = "4"
	Five       = "5"
	Six        = "6"
	Seven      = "7"
	Eight      = "8"
	Nine       = "9"
	Ten        = "10"
	Jack       = "Jack"
	Queen      = "Queen"
	King       = "King"
)

var suitMap = map[Suit]bool{
	Hearts:   true,
	Diamonds: true,
	Clubs:    true,
	Spades:   true,
}

var rankMap = map[Rank]bool{
	Ace:   true,
	Two:   true,
	Three: true,
	Four:  true,
	Five:  true,
	Six:   true,
	Seven: true,
	Eight: true,
	Nine:  true,
	Ten:   true,
	Jack:  true,
	Queen: true,
	King:  true,
}

type Card struct {
	Suit Suit
	Rank Rank
}

type Deck []Card

func MkCard(suit Suit, rank Rank) (Card, error) {
	if _, ok := suitMap[suit]; !ok {
		return Card{}, fmt.Errorf("invalid suit: %s", suit)
	}

	if _, ok := rankMap[rank]; !ok {
		return Card{}, fmt.Errorf("invalid rank: %s", rank)
	}

	return Card{Suit: suit, Rank: rank}, nil
}

func mkDeck() (Deck, error) {
	var deck Deck
	for suit := range suitMap {
		for rank := range rankMap {
			card, err := MkCard(suit, rank)
			if err != nil {
				return deck, err
			}
			deck = append(deck, card)
		}
	}
	return deck, nil
}

func shuffleDeck(deck Deck) {
	for i := range deck {
		j := rand.Intn(i + 1)               // Generate a random index between 0 and i (inclusive)
		deck[i], deck[j] = deck[j], deck[i] // Swap the cards at indices i and j
	}
}

/*
	Game loop
	- Person 1 and 2 connect the game
	- Person 1 and 2 submit their input
	- When all player submit, the server updates the frontend
*/
