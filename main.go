package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

// Table represents an iptables table (e.g., filter, nat).
type Table struct {
	Name   string
	Chains []*Chain
	Rules  []*Rule
}

// Chain represents a single iptables chain within a table.
type Chain struct {
	Name    string
	Policy  string // e.g., ACCEPT, DROP
	Counter string // [packets:bytes]
}

// Rule represents a single iptables rule.
type Rule struct {
	ChainName string
	Rule      string // The full rule string (e.g., "-A DOCKER-USER -j RETURN")
}

// readAndParse reads iptables-save output from an io.Reader and returns a map of tables.
func readAndParse(r io.Reader) (map[string]*Table, error) {
	tables := make(map[string]*Table)
	var currentTable *Table

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 {
			continue
		}

		switch {
		case strings.HasPrefix(line, "*"):
			tableName := line[1:]
			currentTable = &Table{Name: tableName}
			tables[tableName] = currentTable

		case strings.HasPrefix(line, ":"):
			if currentTable != nil {
				parts := strings.Fields(line)
				chain := &Chain{Name: parts[0][1:], Policy: parts[1], Counter: parts[2]}
				currentTable.Chains = append(currentTable.Chains, chain)
			}

		case strings.HasPrefix(line, "-"):
			if currentTable != nil {
				parts := strings.Fields(line)
				rule := &Rule{ChainName: parts[1], Rule: line}
				currentTable.Rules = append(currentTable.Rules, rule)
			}

		case strings.HasPrefix(line, "COMMIT"):
			currentTable = nil

		case strings.HasPrefix(line, "#"):
			// Ignore all comment lines
			continue
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading input: %w", err)
	}
	return tables, nil
}

// filterTables filters out rules and chains based on exclusion patterns, including FORWARD.
func filterTables(tables map[string]*Table, excludePatterns []string) map[string]*Table {
	filteredTables := make(map[string]*Table)

	for _, table := range tables {
		filteredTable := &Table{
			Name: table.Name,
		}

		for _, chain := range table.Chains {
			isExcluded := false
			for _, pattern := range excludePatterns {
				if strings.HasPrefix(chain.Name, pattern) {
					isExcluded = true
					break
				}
			}
			if chain.Name == "FORWARD" {
				isExcluded = true
			}
			if !isExcluded {
				filteredTable.Chains = append(filteredTable.Chains, chain)
			}
		}

		for _, rule := range table.Rules {
			isExcluded := false
			for _, pattern := range excludePatterns {
				if strings.HasPrefix(rule.ChainName, pattern) || strings.Contains(rule.Rule, pattern) {
					isExcluded = true
					break
				}
			}
			if rule.ChainName == "FORWARD" {
				isExcluded = true
			}
			if !isExcluded {
				filteredTable.Rules = append(filteredTable.Rules, rule)
			}
		}

		filteredTables[filteredTable.Name] = filteredTable
	}

	return filteredTables
}

// printRules writes the filtered tables in iptables-restore format to an io.Writer.
func printRules(w io.Writer, tables map[string]*Table) {
	for _, table := range tables {
		fmt.Fprintf(w, "*%s\n", table.Name)

		for _, chain := range table.Chains {
			fmt.Fprintf(w, ":%s %s %s\n", chain.Name, chain.Policy, chain.Counter)
		}

		for _, rule := range table.Rules {
			fmt.Fprintln(w, rule.Rule)
		}

		fmt.Fprintln(w, "COMMIT")
		fmt.Fprintln(w)
	}
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run main.go <input_file> [<output_file>]")
	}

	inputFilePath := os.Args[1]
	inputFile, err := os.Open(inputFilePath)
	if err != nil {
		log.Fatalf("failed to open input file '%s': %v", inputFilePath, err)
	}
	defer inputFile.Close()

	tables, err := readAndParse(inputFile)
	if err != nil {
		log.Fatalf("failed to parse iptables data: %v", err)
	}

	excludePatterns := []string{"DOCKER", "KUBE"}
	filteredTables := filterTables(tables, excludePatterns)

	finalTables := make(map[string]*Table)
	if filterTable, ok := filteredTables["filter"]; ok {
		finalTables["filter"] = filterTable
	}

	var output io.Writer
	if len(os.Args) > 2 {
		outputFilePath := os.Args[2]
		outputFile, err := os.Create(outputFilePath)
		if err != nil {
			log.Fatalf("failed to create output file '%s': %v", outputFilePath, err)
		}
		defer outputFile.Close()
		output = outputFile
	} else {
		output = os.Stdout
	}

	printRules(output, finalTables)
}
