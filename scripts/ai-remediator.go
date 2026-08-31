package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// UpgradeAction represents the clean, structured response we want from the LLM brain
type UpgradeAction struct {
	FilePath string `json:"file_path"`
	Package  string `json:"package"`
	OldVer   string `json:"old_version"`
	NewVer   string `json:"new_version"`
	Analysis string `json:"analysis"` // The AI's human-readable risk & compliance summary
}

// evaluateUpgradesWithAI bundles findings and asks the LLM to write compliance documentation
func evaluateUpgradesWithAI(vulns []string) []UpgradeAction {
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		fmt.Println("⚠️ [AI Client] OPENAI_API_KEY environment variable missing. Defaulting to standard data string.")
		return nil
	}

	// Crafting a precise prompt instructing the model to yield a strict JSON data array
	promptText := fmt.Sprintf(`You are an expert enterprise DevSecOps compliance agent working for a Tier 1 Bank. 
Analyze these vulnerability findings. Provide a non-breaking version upgrade target and write a short, professional, 1-sentence architectural analysis explaining why this upgrade prevents breaking changes for downstream scrum teams.

Findings to evaluate:
%s

Respond strictly with a valid JSON array matching this exact schema layout, with no conversational text or markdown code blocks:
[{"file_path": "string", "package": "string", "old_version": "string", "new_version": "string", "analysis": "string"}]`, strings.Join(vulns, "\n"))

	requestPayload := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]string{
			{"role": "user", "content": promptText},
		},
		"temperature": 0.2, // Low temperature forces the model to remain factual and structured
	}

	jsonBytes, _ := json.Marshal(requestPayload)
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "https://openai.com", bytes.NewBuffer(jsonBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("❌ [AI Network Error] OpenAI connection failure: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	
	var aiResponse struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	
	if err := json.Unmarshal(body, &aiResponse); err != nil || len(aiResponse.Choices) == 0 {
		fmt.Println("❌ [AI Parsing Error] Failed to decode response choice wrappers.")
		return nil
	}

	// Clean out any raw markdown symbols if the model accidentally slips them into the text string
	cleanJSON := aiResponse.Choices.Message.Content
	cleanJSON = strings.TrimPrefix(cleanJSON, "```json")
	cleanJSON = strings.TrimSuffix(cleanJSON, "```")
	cleanJSON = strings.TrimSpace(cleanJSON)

	var actions []UpgradeAction
	if err := json.Unmarshal([]byte(cleanJSON), &actions); err != nil {
		fmt.Printf("❌ [AI Payload Error] LLM response was not valid JSON array syntax: %v\n", err)
		return nil
	}

	return actions
}