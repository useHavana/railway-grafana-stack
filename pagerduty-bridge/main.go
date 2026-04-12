package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

// PagerDuty types

type PagerDutyWebhook struct {
	Event PagerDutyEvent `json:"event"`
}

type PagerDutyEvent struct {
	EventType string            `json:"event_type"`
	Data      PagerDutyIncident `json:"data"`
}

type PagerDutyIncident struct {
	ID      string           `json:"id"`
	Title   string           `json:"title"`
	Urgency string           `json:"urgency"`
	HTMLURL string           `json:"html_url"`
	Service PagerDutyService `json:"service"`
}

type PagerDutyService struct {
	Summary string `json:"summary"`
}

// Grafana types

type GrafanaWebhook struct {
	Status      string         `json:"status"`
	Alerts      []GrafanaAlert `json:"alerts"`
	GroupLabels map[string]string `json:"groupLabels"`
	Title       string         `json:"title"`
	Message     string         `json:"message"`
}

type GrafanaAlert struct {
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     string            `json:"startsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
	DashboardURL string            `json:"dashboardURL"`
	PanelURL     string            `json:"panelURL"`
}

// Devin types

type DevinSessionRequest struct {
	Prompt     string `json:"prompt"`
	PlaybookID string `json:"playbook_id,omitempty"`
}

type DevinSessionResponse struct {
	URL       string `json:"url"`
	SessionID string `json:"session_id"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8090"
	}

	requiredEnvs := []string{"DEVIN_API_KEY", "DEVIN_ORG_ID"}
	for _, env := range requiredEnvs {
		if os.Getenv(env) == "" {
			log.Fatalf("Required environment variable %s is not set", env)
		}
	}

	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/pagerduty", handlePagerDuty)
	http.HandleFunc("/grafana", handleGrafana)

	log.Printf("Alert bridge listening on :%s (endpoints: /pagerduty, /grafana, /health)", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "ok")
}

func handlePagerDuty(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify webhook secret if configured
	webhookSecret := os.Getenv("PAGERDUTY_WEBHOOK_SECRET")
	if webhookSecret != "" {
		if r.Header.Get("X-Webhook-Secret") != webhookSecret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var webhook PagerDutyWebhook
	if err := json.Unmarshal(body, &webhook); err != nil {
		log.Printf("Error parsing webhook: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if webhook.Event.EventType != "incident.triggered" {
		log.Printf("Skipping event type: %s", webhook.Event.EventType)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"skipped","reason":"event_type not incident.triggered"}`)
		return
	}

	incident := webhook.Event.Data
	log.Printf("PagerDuty incident: %s (urgency: %s, service: %s)",
		incident.Title, incident.Urgency, incident.Service.Summary)

	prompt := fmt.Sprintf(`PagerDuty incident triggered:
- Title: %s
- Service: %s
- Urgency: %s
- PagerDuty URL: %s
- Incident ID: %s

Investigate this production incident using the !oncall playbook.
%s`,
		incident.Title,
		incident.Service.Summary,
		incident.Urgency,
		incident.HTMLURL,
		incident.ID,
		investigationSteps,
	)

	sessionURL, err := createDevinSession(prompt)
	if err != nil {
		log.Printf("Error creating Devin session: %v", err)
		http.Error(w, "failed to create devin session", http.StatusInternalServerError)
		return
	}

	log.Printf("Devin session created: %s", sessionURL)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status":        "created",
		"devin_session": sessionURL,
	})
}

func handleGrafana(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify webhook secret if configured
	webhookSecret := os.Getenv("GRAFANA_WEBHOOK_SECRET")
	if webhookSecret != "" {
		if r.Header.Get("X-Webhook-Secret") != webhookSecret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var webhook GrafanaWebhook
	if err := json.Unmarshal(body, &webhook); err != nil {
		log.Printf("Error parsing Grafana webhook: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Only trigger on firing alerts
	if webhook.Status != "firing" {
		log.Printf("Skipping Grafana alert status: %s", webhook.Status)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"skipped","reason":"alert not firing"}`)
		return
	}

	// Build alert summary from all firing alerts
	var alertSummaries []string
	for _, alert := range webhook.Alerts {
		if alert.Status != "firing" {
			continue
		}
		summary := fmt.Sprintf("  - Alert: %s\n    Labels: %v\n    Started: %s\n    Dashboard: %s\n    Panel: %s",
			alert.Labels["alertname"],
			alert.Labels,
			alert.StartsAt,
			alert.DashboardURL,
			alert.PanelURL,
		)
		if desc, ok := alert.Annotations["description"]; ok {
			summary += fmt.Sprintf("\n    Description: %s", desc)
		}
		if runbook, ok := alert.Annotations["runbook_url"]; ok {
			summary += fmt.Sprintf("\n    Runbook: %s", runbook)
		}
		alertSummaries = append(alertSummaries, summary)
	}

	log.Printf("Grafana alert firing: %s (%d alerts)", webhook.Title, len(alertSummaries))

	prompt := fmt.Sprintf(`Grafana alert firing:
- Title: %s
- Message: %s
- Status: %s
- Firing alerts:
%s

Investigate this production incident using the !oncall playbook.
%s`,
		webhook.Title,
		webhook.Message,
		webhook.Status,
		strings.Join(alertSummaries, "\n"),
		investigationSteps,
	)

	sessionURL, err := createDevinSession(prompt)
	if err != nil {
		log.Printf("Error creating Devin session: %v", err)
		http.Error(w, "failed to create devin session", http.StatusInternalServerError)
		return
	}

	log.Printf("Devin session created: %s", sessionURL)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status":        "created",
		"devin_session": sessionURL,
	})
}

const investigationSteps = `
1. Connect to infrastructure via Tailscale
2. Check Grafana Loki logs for errors in the last 30 minutes
3. Check Prometheus metrics for anomalies (error rate, latency, goroutines, memory)
4. Check recent git commits (last 6 hours) for potentially breaking changes
5. If logs suggest DB issues, check pg_stat_activity and slow queries
6. Correlate findings: match error stack traces to recent code changes
7. Report: timeline, root cause, affected scope, severity
8. If code fix needed: open a hotfix PR on branch darin-hotfix-<description>
9. If infrastructure issue: document and escalate to on-call human`

func createDevinSession(prompt string) (string, error) {
	apiKey := os.Getenv("DEVIN_API_KEY")
	orgID := os.Getenv("DEVIN_ORG_ID")
	playbookID := os.Getenv("DEVIN_ONCALL_PLAYBOOK_ID")

	reqBody := DevinSessionRequest{
		Prompt:     prompt,
		PlaybookID: playbookID,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	url := fmt.Sprintf("https://api.devin.ai/v3/organizations/%s/sessions", orgID)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("devin API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var sessionResp DevinSessionResponse
	if err := json.Unmarshal(respBody, &sessionResp); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	return sessionResp.URL, nil
}
