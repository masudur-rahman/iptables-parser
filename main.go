package main

import (
	"bufio"
	"flag"
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

// stringSliceValue is a custom type that implements the flag.Value interface.
type stringSliceValue []string

func (s *stringSliceValue) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceValue) Set(value string) error {
	*s = strings.Split(value, ",")
	return nil
}

// hasString checks if a string exists in a slice.
func hasString(slice []string, s string) bool {
	for _, val := range slice {
		if val == s {
			return true
		}
	}
	return false
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
			continue
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading input: %w", err)
	}
	return tables, nil
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
	inputFilePath := flag.String("input", "", "Path to the input iptables-save file")
	outputFilePath := flag.String("output", "", "Path to the output file (defaults to stdout)")
	var chainsToProcess stringSliceValue
	flag.Var(&chainsToProcess, "chains", "Comma-separated list of chains to process (e.g., INPUT,OUTPUT). Defaults to all chains.")
	var tablesToProcess stringSliceValue
	flag.Var(&tablesToProcess, "tables", "Comma-separated list of tables to process (e.g., filter,nat). Defaults to all tables.")
	flag.Parse()

	if *inputFilePath == "" {
		log.Fatal("Error: --input flag is required")
	}

	inputFile, err := os.Open(*inputFilePath)
	if err != nil {
		log.Fatalf("failed to open input file '%s': %v", *inputFilePath, err)
	}
	defer inputFile.Close()

	allTables, err := readAndParse(inputFile)
	if err != nil {
		log.Fatalf("failed to parse iptables data: %v", err)
	}

	finalTables := make(map[string]*Table)
	var requestedTables []string

	// If no tables are specified, get all of them.
	if len(tablesToProcess) > 0 {
		requestedTables = tablesToProcess
	} else {
		for tableName := range allTables {
			requestedTables = append(requestedTables, tableName)
		}
	}

	for _, tableName := range requestedTables {
		if sourceTable, ok := allTables[tableName]; ok {
			finalTable := &Table{Name: sourceTable.Name}

			// If no chains are specified, get all of them.
			var requestedChains []string
			if len(chainsToProcess) > 0 {
				requestedChains = chainsToProcess
			} else {
				for _, chain := range sourceTable.Chains {
					requestedChains = append(requestedChains, chain.Name)
				}
			}

			for _, chain := range sourceTable.Chains {
				if hasString(requestedChains, chain.Name) {
					finalTable.Chains = append(finalTable.Chains, chain)
				}
			}

			for _, rule := range sourceTable.Rules {
				if hasString(requestedChains, rule.ChainName) {
					finalTable.Rules = append(finalTable.Rules, rule)
				}
			}

			finalTables[finalTable.Name] = finalTable
		}
	}

	var output io.Writer
	if *outputFilePath != "" {
		outputFile, err := os.Create(*outputFilePath)
		if err != nil {
			log.Fatalf("failed to create output file '%s': %v", *outputFilePath, err)
		}
		defer outputFile.Close()
		output = outputFile
	} else {
		output = os.Stdout
	}

	printRules(output, finalTables)
}
