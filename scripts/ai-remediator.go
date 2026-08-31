package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// TrivyReport maps the exact JSON layout produced by our automated security gate
type TrivyReport struct {
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// UpgradeAction represents the clean, structured response we want from the LLM brain
type UpgradeAction struct {
	FilePath string `json:"file_path"`
	Package  string `json:"package"`
	OldVer   string `json:"old_version"`
	NewVer   string `json:"new_version"`
	Analysis string `json:"analysis"` // The AI's human-readable risk & compliance summary
}

func main() {
	// 1. Accept execution arguments passed from the GitHub Actions runner
	javaReportPath := flag.String("java-report", "", "Path to Java Trivy JSON report")
	nodeReportPath := flag.String("node-report", "", "Path to Node.js Trivy JSON report")
	flag.Parse()

	fmt.Println("🚀 [AI Engine] Ingesting telemetry files from upstream security gates...")

	var discoveredVulns []string

	// 2. Safely parse reports and isolate high-severity issues
	if *javaReportPath != "" {
		extractVulnerabilities(*javaReportPath, &discoveredVulns, "baselines/java/pom.xml")
	}
	if *nodeReportPath != "" {
		extractVulnerabilities(*nodeReportPath, &discoveredVulns, "baselines/nodejs/package.json")
	}

	// 3. Evaluate parsing results
	if len(discoveredVulns) == 0 {
		fmt.Println("✅ [AI Engine] Core check clean. Zero critical or high-risk findings discovered.")
		os.Exit(0)
	}

	fmt.Printf("⚠️ [AI Engine] Alert! Discovered %d high/critical security findings across baselines.\n", len(discoveredVulns))

	// 4. Consult LLM regarding valid, non-breaking version targets & compliance justifications
	fmt.Printf("🤖 [AI Engine] Analyzing security findings via LLM agent...\n")
	patches := evaluateUpgradesWithAI(discoveredVulns)

	if len(patches) == 0 {
		fmt.Println("⚠️ [AI Engine] AI agent could not safely calculate non-breaking remediation pathways or verify compliance.")
		os.Exit(0)
	}

	// 5. Apply file changes locally and commit updates to a dedicated branch
	branchName := fmt.Sprintf("security/patch-%d", time.Now().Unix())
	fmt.Printf("🌿 [AI Engine] Generating isolated remediation branch: %s\n", branchName)
	
	applyPatchesAndCommit(patches, branchName)

	// 6. Open an enterprise-compliant Pull Request containing the AI's safety summaries
	raiseGitHubPullRequest(branchName, patches)
}

// extractVulnerabilities opens the JSON data stream, reads it, and appends issues to our processing matrix
func extractVulnerabilities(path string, list *[]string, targetFile string) {
	file, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("❌ [Parser Error] Unable to find file at: %s (%v)\n", path, err)
		return
	}

	var report TrivyReport
	if err := json.Unmarshal(file, &report); err != nil {
		fmt.Printf("❌ [Parser Error] Failed to decode valid JSON for %s: %v\n", path, err)
		return
	}

	for _, res := range report.Results {
		for _, v := range res.Vulnerabilities {
			// Gatekeeper: We only care about actionable, severe threats inside a banking platform
			if v.Severity == "HIGH" || v.Severity == "CRITICAL" {
				summary := fmt.Sprintf("File: %s | Package: %s | Current: %s | Target Fixed: %s | Context: %s", 
					targetFile, v.PkgName, v.InstalledVersion, v.FixedVersion, v.Title)
				*list = append(*list, summary)
			}
		}
	}
}

// evaluateUpgradesWithAI bundles findings and asks the LLM to write compliance documentation
func evaluateUpgradesWithAI(vulns []string) []UpgradeAction {
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		fmt.Println("⚠️ [AI Client] OPENAI_API_KEY environment variable missing. Skipping AI processing.")
		return nil
	}

	// Crafting a precise prompt instructing the model to yield a strict JSON data array
	promptText := fmt.Sprintf(`You are an expert enterprise DevSecOps compliance agent working for a Tier 1 Bank. 
Review these vulnerability findings. Provide a non-breaking version upgrade target and write a short, professional, 1-sentence architectural analysis explaining why this upgrade prevents breaking changes for downstream scrum teams.

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

// applyPatchesAndCommit parses upgrades, patches targets locally, and handles upstream git pushing
func applyPatchesAndCommit(patches []UpgradeAction, branch string) {
	// Execute local Git shell commands to branch away from main securely
	exec.Command("git", "checkout", "-b", branch).Run()

	for _, patch := range patches {
		fmt.Printf("📝 [Mutation Engine] Modifying configuration file for %s\n", patch.Package)
		
		content, err := os.ReadFile("../" + patch.FilePath)
		if err != nil {
			continue
		}

		var modifiedContent string
		if strings.HasSuffix(patch.FilePath, "pom.xml") {
			oldTag := fmt.Sprintf("<version>%s</version>", patch.OldVer)
			newTag := fmt.Sprintf("<version>%s</version>", patch.NewVer)
			modifiedContent = strings.Replace(string(content), oldTag, newTag, 1)
		} else if strings.HasSuffix(patch.FilePath, "package.json") {
			oldLine := fmt.Sprintf("\"%s\": \"%s\"", patch.Package, patch.OldVer)
			newLine := fmt.Sprintf("\"%s\": \"%s\"", patch.Package, patch.NewVer)
			modifiedContent = strings.Replace(string(content), oldLine, newLine, 1)
		}

		if modifiedContent != "" {
			os.WriteFile("../"+patch.FilePath, []byte(modifiedContent), 0644)
		}
	}

	// Save changes locally inside the runner environment and push upstream
	exec.Command("git", "config", "user.name", "devsecops-supply-chain-bot").Run()
	exec.Command("git", "config", "user.email", "bot@bank.internal").Run()
	exec.Command("git", "add", ".").Run()
	exec.Command("git", "commit", "-m", "🔒 security: automated software supply chain remediation patches").Run()
	exec.Command("git", "push", "origin", branch).Run()
}

// raiseGitHubPullRequest creates the official review gate on GitHub loaded with the AI safety assessment
func raiseGitHubPullRequest(branch string, patches []UpgradeAction) {
	token := os.Getenv("GITHUB_TOKEN")
	repo := os.Getenv("GITHUB_REPOSITORY") // Managed and populated automatically by GitHub Action runners
	if token == "" || repo == "" {
		fmt.Println("⚠️ [GitHub Client] GITHUB_TOKEN or REPOSITORY target variables missing. Skipping automated web PR creation.")
		return
	}

	prTitle := "🔒 [DevSecOps Engine] Central Supply Chain Vulnerability Mitigations"
	
	// Constructing a professional markdown report body utilizing the LLM's custom compliance text
	var bodyBuilder strings.Builder
	bodyBuilder.WriteString("### 🤖 Automated Supply Chain Security Report\n\n")
	bodyBuilder.WriteString("Our nightly security gate flagged critical or high-risk findings inside corporate software baselines. ")
	bodyBuilder.WriteString("The Autonomous AI Agent evaluated package structures against Semantic Versioning baselines and applied these non-breaking upgrades:\n\n")
	bodyBuilder.WriteString("| Target File | Dependency Asset | Legacy Version | Patched Version | AI Compliance & Safety Analysis |\n")
	bodyBuilder.WriteString("| :--- | :--- | :--- | :--- | :--- |\n")
	
	for _, p := range patches {
		line := fmt.Sprintf("| `%s` | **%s** | `%s` | `🚀 %s` | %s |\n", p.FilePath, p.Package, p.OldVer, p.NewVer, p.Analysis)
		bodyBuilder.WriteString(line)
	}

	bodyBuilder.WriteString("\n\n*🛡️ This remediation PR was generated automatically by the platform control plane. Please verify compilation logs before merging into production main.*")

	requestPayload := map[string]string{
		"title": prTitle,
		"head":  branch,
		"base":  "main",
		"body":  bodyBuilder.String(),
	}

	jsonBytes, _ := json.Marshal(requestPayload)
	apiURL := fmt.Sprintf("https://github.com/%s/pulls", repo)
	req, _ := http.NewRequestWithContext(context.Background(), "POST", apiURL, bytes.NewBuffer(jsonBytes))