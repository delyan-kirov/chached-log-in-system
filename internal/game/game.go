package game

import (
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

type Player struct {
	Points int
	Cards  []Card
}

type Suit string

const (
	Hearts   Suit = "Hearts"
	Diamonds Suit = "Diamonds"
	Clubs    Suit = "Clubs"
	Spades   Suit = "Spades"
)

type Rank string

const (
	Ace   Rank = "Ace"
	Two   Rank = "2"
	Three Rank = "3"
	Four  Rank = "4"
	Five  Rank = "5"
	Six   Rank = "6"
	Seven Rank = "7"
	Eight Rank = "8"
	Nine  Rank = "9"
	Ten   Rank = "10"
	Jack  Rank = "Jack"
	Queen Rank = "Queen"
	King  Rank = "King"
)

var suitMap = map[Suit]int{
	Hearts:   0,
	Diamonds: 1,
	Clubs:    2,
	Spades:   3,
}

var rankMap = map[Rank]int{
	Ace:   0,
	Two:   1,
	Three: 2,
	Four:  3,
	Five:  4,
	Six:   5,
	Seven: 6,
	Eight: 7,
	Nine:  8,
	Ten:   9,
	Jack:  10,
	Queen: 11,
	King:  12,
}

type Card struct {
	Suit Suit
	Rank Rank
}

type Deck []Card

func MkCard(suit Suit, rank Rank) Card {
	if _, ok := suitMap[suit]; !ok {
		panic("[TYPE_ERROR] Type error when creating card, no suit of tag: " + suit)
	}

	if _, ok := rankMap[rank]; !ok {
		panic("[TYPE_ERROR] Type error when creating card, no rank of tag: " + rank)
	}

	return Card{Suit: suit, Rank: rank}
}

func mkDeck() (Deck, error) {
	var deck Deck
	for suit := range suitMap {
		for rank := range rankMap {
			card := MkCard(suit, rank)
			deck = append(deck, card)
		}
	}
	return deck, nil
}

func isMorePowerful(cardA Card, cardB Card) bool {
	suitApower, _ := suitMap[cardA.Suit]
	suitBpower, _ := suitMap[cardB.Suit]

	rankApower, _ := suitMap[cardA.Suit]
	rankBpower, _ := suitMap[cardB.Suit]

	if suitApower > suitBpower {
		return true
	} else if suitApower == suitBpower && rankApower > rankBpower {
		return true
	} else {
		return false
	}
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
