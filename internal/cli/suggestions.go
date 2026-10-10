package cli

import (
	"math"
	"strings"
)

// Levenshtein calculates the edit distance between two strings.
func Levenshtein(s1, s2 string) int {
	r1, r2 := []rune(s1), []rune(s2)
	l1, l2 := len(r1), len(r2)

	if l1 == 0 {
		return l2
	}
	if l2 == 0 {
		return l1
	}

	col := make([]int, l1+1)
	for i := 0; i <= l1; i++ {
		col[i] = i
	}

	for j := 1; j <= l2; j++ {
		prev := col[0]
		col[0] = j
		for i := 1; i <= l1; i++ {
			temp := col[i]
			cost := 0
			if r1[i-1] != r2[j-1] {
				cost = 1
			}
			col[i] = int(math.Min(
				math.Min(float64(col[i]+1), float64(col[i-1]+1)),
				float64(prev+cost),
			))
			prev = temp
		}
	}

	return col[l1]
}

// SuggestCommand finds closest matching commands for an unknown input.
func SuggestCommand(input string, allCommands []string) []string {
	input = strings.ToLower(input)
	var suggestions []string

	for _, cmd := range allCommands {
		dist := Levenshtein(input, cmd)
		// Suggest if distance <= 2 or if prefix match
		if dist <= 2 || strings.HasPrefix(cmd, input) {
			suggestions = append(suggestions, cmd)
		}
	}

	return suggestions
}
