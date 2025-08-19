package main

import (
	"context"
	"database/sql"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/cloudmailin/cloudmailin-go"
	"github.com/maelvls/foncia/db"
	"github.com/maelvls/foncia/logutil"
)

type MissionOrExpense struct {
	Mission         *db.MissionDB
	Expense         *db.ExpenseDocumentDB
	AccountDocument *db.AccountDocumentDB
}

type tmlpData struct {
	BasePath   string
	SyncStatus string
	NtfyTopic  string
	Items      []MissionOrExpense
	Version    string
	Filter     string
	Search     string
}

var defaultHeaderTmpl = `
<div class="status-info">
	<div>
		<strong>🔔 Notifications:</strong> 
		<a href="https://ntfy.sh/{{.NtfyTopic}}" target="_blank" style="color: var(--primary-color); text-decoration: none;">
			ntfy.sh/{{.NtfyTopic}}
		</a>
	</div>
	<div class="status-badge warning">
		<span>📊</span>
		<span>{{.SyncStatus}}</span>
	</div>
</div>
`

var tmpl = template.Must(template.New("base").Parse(`
<!DOCTYPE html>
<html lang="fr">
<head>
<title>Suivi des factures et ordres de service de la copro TERRA NOSTRA 2</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<style>
		:root {
			--primary-color: #2563eb;
			--primary-light: #3b82f6;
			--primary-dark: #1d4ed8;
			--secondary-color: #64748b;
			--success-color: #10b981;
			--warning-color: #f59e0b;
			--error-color: #ef4444;
			--background-color: #f8fafc;
			--surface-color: #ffffff;
			--text-primary: #1e293b;
			--text-secondary: #64748b;
			--text-muted: #94a3b8;
			--border-color: #e2e8f0;
			--border-light: #f1f5f9;
			--shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
			--shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
			--shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
			--radius-sm: 0.375rem;
			--radius-md: 0.5rem;
			--radius-lg: 0.75rem;
		}

		* {
			box-sizing: border-box;
		}

		body {
			font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
			background-color: var(--background-color);
			color: var(--text-primary);
			line-height: 1.6;
			margin: 0;
			padding: 0;
		}

		.container {
			max-width: 1400px;
			margin: 0 auto;
			padding: 1.5rem 1rem;
		}

		.header {
			background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-light) 100%);
			color: white;
			padding: 1rem 0;
			margin-bottom: 1.5rem;
			border-radius: var(--radius-md);
			box-shadow: var(--shadow-sm);
		}

		.header h1 {
			margin: 0;
			font-size: 1.375rem;
			font-weight: 600;
			text-align: center;
			text-shadow: 0 1px 2px rgba(0,0,0,0.1);
		}

		.dashboard-grid {
			display: grid;
			grid-template-columns: 300px 1fr;
			gap: 1.5rem;
			align-items: start;
		}

		.sidebar {
			display: flex;
			flex-direction: column;
			gap: 1rem;
		}

		.main-content {
			min-width: 0;
		}

		.status-card {
			background: var(--surface-color);
			border-radius: var(--radius-md);
			padding: 1rem;
			box-shadow: var(--shadow-sm);
			border: 1px solid var(--border-color);
		}

		.card-title {
			font-size: 0.875rem;
			font-weight: 600;
			color: var(--text-primary);
			margin-bottom: 0.75rem;
			display: flex;
			align-items: center;
			gap: 0.5rem;
		}

		.filter-card {
			background: var(--surface-color);
			border-radius: var(--radius-md);
			padding: 1rem;
			box-shadow: var(--shadow-sm);
			border: 1px solid var(--border-color);
		}

		.search-section {
			margin-bottom: 1rem;
		}

		.search-input {
			width: 100%;
			padding: 0.75rem;
			border: 1px solid var(--border-color);
			border-radius: var(--radius-sm);
			font-size: 0.875rem;
			background: var(--background-color);
			color: var(--text-primary);
			transition: border-color 0.2s ease, box-shadow 0.2s ease;
		}

		.search-input:focus {
			outline: none;
			border-color: var(--primary-color);
			box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
		}

		.search-input::placeholder {
			color: var(--text-muted);
		}

		.filter-options {
			display: flex;
			flex-direction: column;
			gap: 0.75rem;
		}

		.filter-option {
			display: flex;
			align-items: center;
			gap: 0.5rem;
			padding: 0.5rem;
			border-radius: var(--radius-sm);
			transition: background-color 0.2s ease;
		}

		.filter-option:hover {
			background-color: var(--border-light);
		}

		.filter-option input[type="radio"] {
			width: 1rem;
			height: 1rem;
			accent-color: var(--primary-color);
		}

		.filter-option label {
			font-size: 0.8125rem;
			color: var(--text-secondary);
			cursor: pointer;
			user-select: none;
			flex: 1;
		}

		.filter-button {
			background: var(--primary-color);
			color: white;
			border: none;
			padding: 0.5rem 1rem;
			border-radius: var(--radius-sm);
			font-size: 0.8125rem;
			font-weight: 500;
			cursor: pointer;
			transition: all 0.2s ease;
			box-shadow: var(--shadow-sm);
			width: 100%;
			margin-top: 0.5rem;
		}

		.filter-button:hover {
			background: var(--primary-dark);
			transform: translateY(-1px);
			box-shadow: var(--shadow-md);
		}

		.stats-card {
			background: var(--surface-color);
			border-radius: var(--radius-md);
			padding: 1rem;
			box-shadow: var(--shadow-sm);
			border: 1px solid var(--border-color);
		}

		.stats-grid {
			display: grid;
			grid-template-columns: 1fr 1fr;
			gap: 0.75rem;
		}

		.stat-item {
			text-align: center;
			padding: 0.5rem;
			background: var(--background-color);
			border-radius: var(--radius-sm);
		}

		.stat-number {
			font-size: 1.25rem;
			font-weight: 700;
			color: var(--primary-color);
		}

		.stat-label {
			font-size: 0.75rem;
			color: var(--text-muted);
			margin-top: 0.25rem;
		}

		/* Main content area styles */
		.main-content {
			display: flex;
			flex-direction: column;
			overflow: auto;
		}

		.data-table {
			display: flex;
			flex-direction: column;
			height: 100%;
		}

		.table-header {
			display: flex;
			justify-content: space-between;
			align-items: center;
			margin-bottom: 1.5rem;
			padding: 0 0.5rem;
		}

		.table-title {
			font-size: 1.25rem;
			font-weight: 600;
			color: var(--text-primary);
		}

		.table-controls {
			display: flex;
			align-items: center;
			gap: 1rem;
		}

		.view-toggle {
			display: flex;
			background: var(--bg-secondary);
			border-radius: var(--border-radius);
			padding: 0.25rem;
			border: 1px solid var(--border-color);
		}

		.view-option {
			padding: 0.5rem 1rem;
			border: none;
			background: transparent;
			color: var(--text-secondary);
			border-radius: calc(var(--border-radius) - 0.25rem);
			cursor: pointer;
			transition: all 0.2s ease;
			font-size: 0.875rem;
			font-weight: 500;
		}

		.view-option:hover {
			color: var(--text-primary);
			background: var(--bg-primary);
		}

		.view-option.active {
			color: var(--primary-color);
			background: var(--bg-primary);
			box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
		}

		/* Card view styles */
		.items-grid {
			display: grid;
			grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
			gap: 1.5rem;
			padding: 0.5rem;
		}

		.item-card {
			background: var(--bg-primary);
			border: 1px solid var(--border-color);
			border-radius: var(--border-radius-lg);
			padding: 1.5rem;
			transition: all 0.3s ease;
			box-shadow: var(--shadow-sm);
		}

		.item-card:hover {
			transform: translateY(-2px);
			box-shadow: var(--shadow-lg);
			border-color: var(--primary-color);
		}

		.item-header {
			display: flex;
			justify-content: space-between;
			align-items: center;
			margin-bottom: 1rem;
		}

		.item-date {
			font-size: 0.875rem;
			color: var(--text-secondary);
			font-weight: 500;
		}

		.item-content {
			margin-bottom: 1rem;
		}

		.item-title {
			font-size: 1.125rem;
			font-weight: 600;
			color: var(--text-primary);
			margin-bottom: 0.5rem;
			line-height: 1.4;
		}

		.item-description {
			color: var(--text-secondary);
			font-size: 0.9375rem;
			line-height: 1.5;
		}

		.item-footer {
			display: flex;
			justify-content: space-between;
			align-items: center;
			padding-top: 1rem;
			border-top: 1px solid var(--border-color);
		}

		/* Stats card styles */
		.stats-card {
			background: var(--bg-primary);
			border: 1px solid var(--border-color);
			border-radius: var(--border-radius-lg);
			padding: 1.5rem;
			box-shadow: var(--shadow-sm);
		}

		.stats-grid {
			display: grid;
			grid-template-columns: 1fr 1fr;
			gap: 1rem;
			margin-top: 1rem;
		}

		.stat-item {
			text-align: center;
			padding: 0.75rem;
			background: var(--bg-secondary);
			border-radius: var(--border-radius);
			border: 1px solid var(--border-color);
		}

		.stat-number {
			font-size: 1.5rem;
			font-weight: 700;
			color: var(--primary-color);
			margin-bottom: 0.25rem;
		}

		.stat-label {
			font-size: 0.75rem;
			color: var(--text-secondary);
			text-transform: uppercase;
			font-weight: 600;
			letter-spacing: 0.025em;
		}

		/* Filter card styles */
		.filter-card {
			background: var(--bg-primary);
			border: 1px solid var(--border-color);
			border-radius: var(--border-radius-lg);
			padding: 1.5rem;
			box-shadow: var(--shadow-sm);
		}

		.filter-options {
			display: flex;
			flex-direction: column;
			gap: 0.75rem;
			margin-top: 1rem;
		}

		.filter-option {
			display: flex;
			align-items: center;
			gap: 0.75rem;
		}

		.filter-option input[type="radio"] {
			width: 1rem;
			height: 1rem;
		}

		.filter-option label {
			font-size: 0.9375rem;
			color: var(--text-primary);
			cursor: pointer;
			flex: 1;
		}

		.filter-button {
			width: 100%;
			padding: 0.75rem;
			margin-top: 1rem;
			background: var(--primary-color);
			color: white;
			border: none;
			border-radius: var(--border-radius);
			font-size: 0.9375rem;
			font-weight: 600;
			cursor: pointer;
			transition: all 0.2s ease;
		}

		.filter-button:hover {
			background: var(--primary-hover);
			transform: translateY(-1px);
			box-shadow: var(--shadow-md);
		}		.table-header {
			background: var(--background-color);
			padding: 1rem;
			border-bottom: 1px solid var(--border-color);
			display: flex;
			justify-content: space-between;
			align-items: center;
		}

		.table-title {
			font-size: 1rem;
			font-weight: 600;
			color: var(--text-primary);
			display: flex;
			align-items: center;
			gap: 0.5rem;
		}

		.table-controls {
			display: flex;
			gap: 0.5rem;
			align-items: center;
		}

		.view-toggle {
			display: flex;
			background: var(--border-light);
			border-radius: var(--radius-sm);
			padding: 0.125rem;
		}

		.view-option {
			padding: 0.375rem 0.75rem;
			font-size: 0.75rem;
			border: none;
			background: transparent;
			color: var(--text-muted);
			cursor: pointer;
			border-radius: var(--radius-sm);
			transition: all 0.2s ease;
		}

		.view-option.active {
			background: var(--surface-color);
			color: var(--text-primary);
			box-shadow: var(--shadow-sm);
		}

		.items-grid {
			display: grid;
			grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
			gap: 1rem;
			padding: 1rem;
		}

		.item-card {
			background: var(--surface-color);
			border: 1px solid var(--border-color);
			border-radius: var(--radius-md);
			padding: 1rem;
			transition: all 0.2s ease;
		}

		.item-card:hover {
			border-color: var(--primary-color);
			box-shadow: var(--shadow-md);
			transform: translateY(-2px);
		}

		.item-header {
			display: flex;
			justify-content: space-between;
			align-items: flex-start;
			margin-bottom: 0.75rem;
		}

		.item-date {
			font-size: 0.75rem;
			color: var(--text-muted);
			font-weight: 500;
		}

		.item-content {
			margin-bottom: 0.75rem;
		}

		.item-title {
			font-size: 0.875rem;
			font-weight: 600;
			color: var(--text-primary);
			margin-bottom: 0.25rem;
		}

		.item-description {
			font-size: 0.8125rem;
			color: var(--text-secondary);
			line-height: 1.4;
		}

		.item-footer {
			display: flex;
			justify-content: space-between;
			align-items: center;
			padding-top: 0.75rem;
			border-top: 1px solid var(--border-light);
		}

		/* Table styles */
		#table-view {
			background: var(--bg-primary);
			border-radius: var(--border-radius-lg);
			box-shadow: var(--shadow-sm);
			border: 1px solid var(--border-color);
			overflow: hidden;
		}

		table {
			width: 100%;
			border-collapse: collapse;
			font-size: 0.8125rem;
		}

		table th {
			background: var(--background-color);
			padding: 0.75rem;
			font-weight: 600;
			text-align: left;
			color: var(--text-primary);
			border-bottom: 1px solid var(--border-color);
		}

		table td {
			padding: 0.75rem;
			border-bottom: 1px solid var(--border-light);
			vertical-align: top;
		}

		table tr:hover {
			background: var(--border-light);
		}

		@media (max-width: 1024px) {
			.dashboard-grid {
				grid-template-columns: 250px 1fr;
				gap: 1rem;
			}
		}

		@media (max-width: 768px) {
			.container {
				padding: 1rem 0.5rem;
			}

			.dashboard-grid {
				grid-template-columns: 1fr;
				gap: 1rem;
			}

			.sidebar {
				order: 2;
			}

			.main-content {
				order: 1;
			}

			.stats-grid {
				grid-template-columns: repeat(4, 1fr);
			}

			.items-grid {
				grid-template-columns: 1fr;
			}

			.table-header {
				flex-direction: column;
				gap: 0.75rem;
				align-items: stretch;
			}
		}

		.status-info {
			display: flex;
			align-items: center;
			gap: 1rem;
			flex-wrap: wrap;
		}

		.status-badge {
			display: inline-flex;
			align-items: center;
			gap: 0.5rem;
			padding: 0.5rem 1rem;
			border-radius: var(--radius-sm);
			font-size: 0.875rem;
			font-weight: 500;
		}

		.status-badge.success {
			background-color: #dcfce7;
			color: #166534;
		}

		.status-badge.warning {
			background-color: #fef3c7;
			color: #92400e;
		}

		.status-badge.error {
			background-color: #fee2e2;
			color: #991b1b;
		}

		.filter-panel {
			background: var(--surface-color);
			border-radius: var(--radius-md);
			padding: 1.5rem;
			margin-bottom: 2rem;
			box-shadow: var(--shadow-sm);
			border: 1px solid var(--border-color);
		}

		.filter-title {
			font-size: 1.125rem;
			font-weight: 600;
			margin-bottom: 1rem;
			color: var(--text-primary);
			cursor: pointer;
			display: flex;
			align-items: center;
			gap: 0.5rem;
			user-select: none;
		}

		.filter-title:hover {
			color: var(--primary-color);
		}

		.filter-chevron {
			transition: transform 0.2s ease;
			font-size: 0.875rem;
		}

		.filter-content {
			max-height: 0;
			overflow: hidden;
			transition: max-height 0.3s ease;
		}

		.filter-content.expanded {
			max-height: 200px;
		}

		.filter-options {
			display: flex;
			flex-wrap: wrap;
			gap: 1rem;
			align-items: center;
		}

		.filter-option {
			display: flex;
			align-items: center;
			gap: 0.5rem;
		}

		.filter-option input[type="radio"] {
			width: 1.125rem;
			height: 1.125rem;
			accent-color: var(--primary-color);
		}

		.filter-option label {
			font-size: 0.875rem;
			color: var(--text-secondary);
			cursor: pointer;
			user-select: none;
		}

		.filter-button {
			background: var(--primary-color);
			color: white;
			border: none;
			padding: 0.625rem 1.25rem;
			border-radius: var(--radius-sm);
			font-size: 0.875rem;
			font-weight: 500;
			cursor: pointer;
			transition: all 0.2s ease;
			box-shadow: var(--shadow-sm);
		}

		.filter-button:hover {
			background: var(--primary-dark);
			transform: translateY(-1px);
			box-shadow: var(--shadow-md);
		}

		.data-table {
			background: var(--surface-color);
			border-radius: var(--radius-lg);
			overflow: hidden;
			box-shadow: var(--shadow-md);
			border: 1px solid var(--border-color);
		}

		table {
			width: 100%;
			border-collapse: collapse;
			font-size: 0.875rem;
		}

		table th {
			background: var(--background-color);
			padding: 1rem;
			font-weight: 600;
			text-align: left;
			color: var(--text-primary);
			border-bottom: 2px solid var(--border-color);
			position: sticky;
			top: 0;
			z-index: 10;
		}

		table td {
			padding: 1rem;
			border-bottom: 1px solid var(--border-light);
			vertical-align: top;
		}

		table tr:hover {
			background: var(--background-color);
		}

		.date-cell {
			font-weight: 500;
			color: var(--text-primary);
			white-space: nowrap;
		}

		.date-cell a {
			color: var(--primary-color);
			text-decoration: none;
			font-weight: 600;
		}

		.date-cell a:hover {
			text-decoration: underline;
		}

		.type-cell {
			display: flex;
			flex-direction: column;
			gap: 0.25rem;
		}

		.type-badge {
			display: inline-flex;
			align-items: center;
			padding: 0.25rem 0.75rem;
			border-radius: var(--radius-sm);
			font-size: 0.75rem;
			font-weight: 500;
			width: fit-content;
		}

		.type-badge.mission {
			background-color: #dbeafe;
			color: #1e40af;
		}

		.type-badge.expense {
			background-color: #dcfce7;
			color: #166534;
		}

		.type-badge.document {
			background-color: #f3e8ff;
			color: #7c3aed;
		}

		.status-text {
			font-size: 0.75rem;
			color: var(--text-muted);
			margin-top: 0.25rem;
		}

		.label-cell {
			font-weight: 500;
			color: var(--text-primary);
		}

		.description-cell {
			color: var(--text-secondary);
			font-size: 0.8125rem;
			max-width: 300px;
		}

		.file-link {
			display: inline-flex;
			align-items: center;
			gap: 0.25rem;
			color: var(--primary-color);
			text-decoration: none;
			font-size: 0.8125rem;
			padding: 0.25rem 0.5rem;
			border-radius: var(--radius-sm);
			transition: background-color 0.2s ease;
		}

		.file-link:hover {
			background-color: var(--border-light);
			text-decoration: none;
		}

		.file-status {
			color: var(--text-muted);
			font-style: italic;
			font-size: 0.8125rem;
		}

		.footer {
			text-align: center;
			margin-top: 2rem;
			padding: 1rem;
			color: var(--text-muted);
			font-size: 0.8125rem;
		}

		/* Mobile responsive design */
		@media (max-width: 768px) {
			.dashboard-grid {
				grid-template-columns: 1fr;
				grid-template-rows: auto 1fr;
				gap: 1rem;
			}

			.sidebar {
				display: flex;
				flex-direction: row;
				gap: 1rem;
				overflow-x: auto;
				padding-bottom: 0.5rem;
			}

			.sidebar > * {
				flex: 0 0 280px;
			}

			.items-grid {
				grid-template-columns: 1fr;
				gap: 1rem;
			}

			.item-card {
				padding: 1rem;
			}

			.stats-grid {
				grid-template-columns: repeat(4, 1fr);
			}

			.stat-item {
				padding: 0.5rem;
			}

			.stat-number {
				font-size: 1.25rem;
			}

			.table-header {
				flex-direction: column;
				align-items: stretch;
				gap: 1rem;
			}

			.view-toggle {
				justify-content: center;
			}

			.container {
				padding: 1rem 0.5rem;
			}

			.header h1 {
				font-size: 1.5rem;
			}

			table {
				font-size: 0.8125rem;
			}

			table th,
			table td {
				padding: 0.75rem 0.5rem;
			}

			.description-cell {
				max-width: 200px;
			}
		}

		@media (max-width: 640px) {
			table th:nth-child(4),
			table td:nth-child(4) {
				display: none;
			}
		}

		@media (max-width: 480px) {
			.sidebar {
				flex-direction: column;
			}

			.sidebar > * {
				flex: none;
			}

			.stats-grid {
				grid-template-columns: 1fr 1fr;
			}

			.container {
				padding: 0.75rem;
			}

			.header h1 {
				font-size: 1.25rem;
			}
		}
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>🏢 Suivi des factures et ordres de service</h1>
			<p style="text-align: center; margin: 0.25rem 0 0 0; opacity: 0.8; font-size: 0.8125rem;">TERRA NOSTRA 2</p>
		</div>

		<div class="dashboard-grid">
			<div class="sidebar">
				<div class="status-card">
					<div class="card-title">📊 État du système</div>
					{{ template "header" . }}
				</div>

				<div class="filter-card">
					<div class="card-title">🔍 Filtres</div>
					<form action="/" method="GET">
						<div class="search-section">
							<input type="text" id="search" name="search" placeholder="Rechercher par nom de fichier, label ou description..." value="{{.Search}}" class="search-input">
						</div>
						<div class="filter-options">
							<div class="filter-option">
								<input type="radio" id="all" name="filter" value="" {{if eq .Filter ""}}checked{{end}}>
								<label for="all">Tous les éléments</label>
							</div>

							<div class="filter-option">
								<input type="radio" id="expenses" name="filter" value="expenses" {{if eq .Filter "expenses"}}checked{{end}}>
								<label for="expenses">💰 Factures</label>
							</div>

							<div class="filter-option">
								<input type="radio" id="missions" name="filter" value="missions" {{if eq .Filter "missions"}}checked{{end}}>
								<label for="missions">🔧 Missions</label>
							</div>

							<div class="filter-option">
								<input type="radio" id="visits" name="filter" value="visits" {{if eq .Filter "visits"}}checked{{end}}>
								<label for="visits">📋 Rapports</label>
							</div>
						</div>
						<button type="submit" class="filter-button">Appliquer</button>
					</form>
				</div>

				<div class="stats-card">
					<div class="card-title">📈 Statistiques</div>
					<div class="stats-grid">
						<div class="stat-item">
							<div class="stat-number" id="total-items">{{len .Items}}</div>
							<div class="stat-label">Total</div>
						</div>
						<div class="stat-item">
							<div class="stat-number" id="expenses-count">0</div>
							<div class="stat-label">Factures</div>
						</div>
						<div class="stat-item">
							<div class="stat-number" id="missions-count">0</div>
							<div class="stat-label">Missions</div>
						</div>
						<div class="stat-item">
							<div class="stat-number" id="documents-count">0</div>
							<div class="stat-label">Documents</div>
						</div>
					</div>
				</div>
			</div>

			<div class="main-content">
				<div class="data-table">
					<div class="table-header">
						<div class="table-title">
							<span>� Données</span>
						</div>
						<div class="table-controls">
							<div class="view-toggle">
								<button class="view-option active" onclick="switchView('table')">Table</button>
								<button class="view-option" onclick="switchView('cards')">Cartes</button>
							</div>
						</div>
					</div>

					<div id="table-view">
						<table>
							<thead>
								<tr>
									<th>Date</th>
									<th>Type</th>
									<th>Label</th>
									<th>Description</th>
									<th>Document</th>
								</tr>
							</thead>
							<tbody>
								{{range .Items}}
									{{with .Mission}}
									<tr id="{{ .ID }}">
										<td class="date-cell"><a href="{{$.BasePath}}#{{ .ID }}">{{.StartedAt.Format "02 Jan 2006"}}</a></td>
										<td class="type-cell">
											<span class="type-badge mission">{{ .KindFrench }}</span>
											<div class="status-text">{{ .StatusFrench }}</div>
										</td>
										<td class="label-cell">{{.Label}}</td>
										<td class="description-cell">{{.Description}}</td>
										<td>
											{{range .WorkOrders}}
												<div style="margin-bottom: 0.5rem;">
													<strong>{{.Number}}</strong> {{.Label}}<br>
													<small>{{.RepairDateEnd.Format "02/01/2006"}} - {{.Supplier.Name}}</small>
													{{range .Supplier.Documents}}
														<br><a href="{{$.BasePath}}/dl/contract/{{.HashFile}}/{{.FilePath}}" class="file-link">📄 {{.FilePath}}</a>
													{{end}}
												</div>
											{{end}}
										</td>
									</tr>
									{{end}}
									{{with .Expense}}
									<tr id="{{or .HashFile .InvoiceID}}">
										<td class="date-cell"><a href="{{$.BasePath}}#{{ or .HashFile .InvoiceID }}">{{.Date.Format "02 Jan 2006"}}</a></td>
										<td class="type-cell">
											<span class="type-badge expense">💰 Facture</span>
											{{if eq .Source "repairs"}}
												<div class="status-text">(compte travaux)</div>
											{{end}}
										</td>
										<td class="label-cell">{{.Label}}</td>
										<td class="description-cell">{{.Amount}}</td>
										<td>
											{{if .FilePath}}
												{{if .HashFile}}
													<a href="{{$.BasePath}}/dl/invoice/{{.HashFile}}/{{.Filename}}" class="file-link">📄 {{.Filename}}</a>
												{{else if .InvoiceID}}
													<a href="{{$.BasePath}}/dl/invoiceid/{{.InvoiceID}}/{{.Filename}}" class="file-link">📄 {{.Filename}}</a>
												{{end}}
											{{else if .HashFile}}
												<span class="file-status">⏳ En attente</span>
											{{else}}
												<span class="file-status">❌ Pas de PDF</span>
											{{end}}
										</td>
									</tr>
									{{end}}
									{{with .AccountDocument}}
									<tr id="{{.ID}}">
										<td class="date-cell"><a href="{{$.BasePath}}#{{.ID}}">{{.CreatedAt.Format "02 Jan 2006"}}</a></td>
										<td class="type-cell">
											<span class="type-badge document">📋 Document</span>
										</td>
										<td class="label-cell">{{.CategoryFrench}}</td>
										<td class="description-cell">{{.MimeType}}</td>
										<td>
											{{if .FilePath}}
												<a href="{{$.BasePath}}/dl/doc/{{.HashFile}}/{{.Filename}}" class="file-link">📄 {{.Filename}}</a>
											{{else}}
												<span class="file-status">⏳ En attente</span>
											{{end}}
										</td>
									</tr>
									{{end}}
								{{end}}
							</tbody>
						</table>
					</div>

					<div id="cards-view" class="items-grid" style="display: none;">
						{{range .Items}}
							{{with .Mission}}
							<div class="item-card" id="card-{{ .ID }}">
								<div class="item-header">
									<span class="type-badge mission">{{ .KindFrench }}</span>
									<span class="item-date">{{.StartedAt.Format "02 Jan 2006"}}</span>
								</div>
								<div class="item-content">
									<div class="item-title">{{.Label}}</div>
									<div class="item-description">{{.Description}}</div>
								</div>
								<div class="item-footer">
									<span class="status-text">{{ .StatusFrench }}</span>
									{{range .WorkOrders}}
										{{range .Supplier.Documents}}
											<a href="{{$.BasePath}}/dl/contract/{{.HashFile}}/{{.FilePath}}" class="file-link">📄</a>
										{{end}}
									{{end}}
								</div>
							</div>
							{{end}}
							{{with .Expense}}
							<div class="item-card" id="card-{{or .HashFile .InvoiceID}}">
								<div class="item-header">
									<span class="type-badge expense">💰 Facture</span>
									<span class="item-date">{{.Date.Format "02 Jan 2006"}}</span>
								</div>
								<div class="item-content">
									<div class="item-title">{{.Label}}</div>
									<div class="item-description">{{.Amount}}</div>
								</div>
								<div class="item-footer">
									{{if eq .Source "repairs"}}
										<span class="status-text">Compte travaux</span>
									{{else}}
										<span class="status-text">Compte courant</span>
									{{end}}
									{{if .FilePath}}
										{{if .HashFile}}
											<a href="{{$.BasePath}}/dl/invoice/{{.HashFile}}/{{.Filename}}" class="file-link">📄</a>
										{{else if .InvoiceID}}
											<a href="{{$.BasePath}}/dl/invoiceid/{{.InvoiceID}}/{{.Filename}}" class="file-link">📄</a>
										{{end}}
									{{end}}
								</div>
							</div>
							{{end}}
							{{with .AccountDocument}}
							<div class="item-card" id="card-{{.ID}}">
								<div class="item-header">
									<span class="type-badge document">📋 Document</span>
									<span class="item-date">{{.CreatedAt.Format "02 Jan 2006"}}</span>
								</div>
								<div class="item-content">
									<div class="item-title">{{.CategoryFrench}}</div>
									<div class="item-description">{{.MimeType}}</div>
								</div>
								<div class="item-footer">
									<span class="status-text">Document</span>
									{{if .FilePath}}
										<a href="{{$.BasePath}}/dl/doc/{{.HashFile}}/{{.Filename}}" class="file-link">📄</a>
									{{end}}
								</div>
							</div>
							{{end}}
						{{end}}
					</div>
				</div>
			</div>
		</div>

		<div class="footer">
			<small>Version: {{.Version}}</small>
		</div>
	</div>

	<script>
		function switchView(viewType) {
			const tableView = document.getElementById('table-view');
			const cardsView = document.getElementById('cards-view');
			const buttons = document.querySelectorAll('.view-option');
			
			buttons.forEach(btn => btn.classList.remove('active'));
			
			if (viewType === 'table') {
				tableView.style.display = 'block';
				cardsView.style.display = 'none';
				document.querySelector('.view-option[onclick="switchView(\'table\')"]').classList.add('active');
			} else {
				tableView.style.display = 'none';
				cardsView.style.display = 'grid';
				document.querySelector('.view-option[onclick="switchView(\'cards\')"]').classList.add('active');
			}
			
			// Re-apply search filter when switching views
			const searchInput = document.getElementById('search');
			if (searchInput && searchInput.value.trim()) {
				performSearch(searchInput.value.trim());
			}
			
			updateStats();
		}

		// Calculate and update statistics
		function updateStats() {
			const tableView = document.getElementById('table-view');
			const cardsView = document.getElementById('cards-view');
			const isTableView = tableView.style.display !== 'none';
			
			let expenses = 0, missions = 0, documents = 0;
			
			if (isTableView) {
				const rows = document.querySelectorAll('tbody tr');
				rows.forEach(row => {
					if (row.style.display !== 'none') {
						if (row.querySelector('.type-badge.expense')) expenses++;
						else if (row.querySelector('.type-badge.mission')) missions++;
						else if (row.querySelector('.type-badge.document')) documents++;
					}
				});
			} else {
				const cards = document.querySelectorAll('.item-card');
				cards.forEach(card => {
					if (card.style.display !== 'none') {
						if (card.querySelector('.type-badge.expense')) expenses++;
						else if (card.querySelector('.type-badge.mission')) missions++;
						else if (card.querySelector('.type-badge.document')) documents++;
					}
				});
			}
			
			document.getElementById('expenses-count').textContent = expenses;
			document.getElementById('missions-count').textContent = missions;
			document.getElementById('documents-count').textContent = documents;
			document.getElementById('total-items').textContent = expenses + missions + documents;
		}

		// Real-time search functionality
		function performSearch(query) {
			query = query.toLowerCase();
			const tableRows = document.querySelectorAll('tbody tr');
			const itemCards = document.querySelectorAll('.item-card');
			
			// Filter table rows
			tableRows.forEach(row => {
				const label = row.querySelector('.label-cell')?.textContent?.toLowerCase() || '';
				const description = row.querySelector('.description-cell')?.textContent?.toLowerCase() || '';
				const fileLinks = Array.from(row.querySelectorAll('.file-link')).map(link => 
					link.textContent?.toLowerCase() || ''
				).join(' ');
				
				const matches = label.includes(query) || 
								description.includes(query) || 
								fileLinks.includes(query);
								
				row.style.display = matches ? '' : 'none';
			});
			
			// Filter cards
			itemCards.forEach(card => {
				const title = card.querySelector('.item-title')?.textContent?.toLowerCase() || '';
				const description = card.querySelector('.item-description')?.textContent?.toLowerCase() || '';
				const fileLinks = Array.from(card.querySelectorAll('.file-link')).map(link => 
					link.getAttribute('href')?.toLowerCase() || ''
				).join(' ');
				
				const matches = title.includes(query) || 
								description.includes(query) || 
								fileLinks.includes(query);
								
				card.style.display = matches ? '' : 'none';
			});
			
			updateStats();
		}

		// Initialize search functionality
		document.addEventListener('DOMContentLoaded', function() {
			const searchInput = document.getElementById('search');
			if (searchInput) {
				// Real-time search as user types
				searchInput.addEventListener('input', function() {
					const query = this.value.trim();
					if (query === '') {
						// Show all items when search is empty
						document.querySelectorAll('tbody tr').forEach(row => row.style.display = '');
						document.querySelectorAll('.item-card').forEach(card => card.style.display = '');
					} else {
						performSearch(query);
					}
					updateStats();
				});
				
				// Perform initial search if there's a search value
				const initialSearch = searchInput.value.trim();
				if (initialSearch) {
					performSearch(initialSearch);
				}
			}
			
			updateStats();
		});

		// Initialize stats on page load
		document.addEventListener('DOMContentLoaded', updateStats);
	</script>
</body>
</html>
`))

type tmlpErrData struct {
	Error   string
	Version string
}

var tmlpErr = template.Must(template.New("").Parse(`<!DOCTYPE html>
<html lang="fr">
<head>
<title>Erreur - Suivi TERRA NOSTRA 2</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
	:root {
		--primary-color: #2563eb;
		--error-color: #ef4444;
		--background-color: #f8fafc;
		--surface-color: #ffffff;
		--text-primary: #1e293b;
		--text-secondary: #64748b;
		--border-color: #e2e8f0;
		--shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
		--radius-md: 0.5rem;
		--radius-lg: 0.75rem;
	}

	body {
		font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
		background-color: var(--background-color);
		color: var(--text-primary);
		margin: 0;
		padding: 2rem;
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
	}

	.error-container {
		background: var(--surface-color);
		border-radius: var(--radius-lg);
		padding: 3rem;
		box-shadow: var(--shadow-md);
		border: 1px solid var(--border-color);
		text-align: center;
		max-width: 500px;
		width: 100%;
	}

	.error-icon {
		font-size: 4rem;
		margin-bottom: 1rem;
	}

	.error-title {
		color: var(--error-color);
		font-size: 1.5rem;
		font-weight: 700;
		margin-bottom: 1rem;
	}

	.error-message {
		color: var(--text-secondary);
		margin-bottom: 2rem;
		line-height: 1.6;
	}

	.version-info {
		color: var(--text-secondary);
		font-size: 0.875rem;
		border-top: 1px solid var(--border-color);
		padding-top: 1rem;
		margin-top: 2rem;
	}

	.back-button {
		background: var(--primary-color);
		color: white;
		text-decoration: none;
		padding: 0.75rem 1.5rem;
		border-radius: var(--radius-md);
		font-weight: 500;
		display: inline-block;
		transition: background-color 0.2s ease;
	}

	.back-button:hover {
		background: #1d4ed8;
	}
</style>
</head>
<body>
	<div class="error-container">
		<div class="error-icon">❌</div>
		<h1 class="error-title">Une erreur est survenue</h1>
		<p class="error-message">{{.Error}}</p>
		<a href="/" class="back-button">← Retour à l'accueil</a>
		<div class="version-info">Version: {{.Version}}</div>
	</div>
</body>
</html>
`))

func logRequest(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logutil.Debugf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
		next(w, r)
	}
}

// Serve the HTTP UI. This func is blocking and can be unblocked by cancelling
// the context. The `basePath` should always start with a slash and not end with
// a slash. If you want to given an empty base path, don't give "/". Instead,
// give "".
func ServeHTTP(ctx context.Context, db *sql.DB, httpListen net.Listener, client *http.Client, uuid, basePath string, lastSync func() (time.Time, error), htmlHeader string) error {
	if basePath != "" && !strings.HasPrefix(basePath, "/") {
		return fmt.Errorf("base path must start with a slash or be an empty string")
	}
	if strings.HasSuffix(basePath, "/") {
		return fmt.Errorf("base path must not end with a slash; if you want to give the base path /, give an empty string instead")
	}

	headerContents := defaultHeaderTmpl
	if htmlHeader != "" {
		headerContents = htmlHeader
	}
	_, err := tmpl.New("header").Parse(headerContents)
	if err != nil {
		return fmt.Errorf("while parsing HTML header file %s: %w", *htmlHeaderFile, err)
	}

	// HTTP server to serve the list of missions and expenses.
	mux := http.NewServeMux()
	s := http.Server{Handler: mux}
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	err = addHandlers(mux, db, client, uuid, basePath, lastSync)
	if err != nil {
		return fmt.Errorf("while adding handlers: %w", err)
	}

	logutil.Infof("listening on %v", httpListen.Addr())
	logutil.Infof("url: http://%s%s", httpListen.Addr(), basePath)

	err = s.Serve(httpListen)
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("while serving HTTP: %w", err)
	}

	return nil
}

func addHandlers(mux *http.ServeMux, sqlDB *sql.DB, client *http.Client, uuid, basePath string, lastSync func() (time.Time, error)) error {
	// Download a PDF. The /invoice endpoint historically relies on hash files,
	// that's why a second endpoint /invoiceid was added to support invoice IDs.
	//
	//  GET /dl/invoice/660d79500178f21ab3ffc357/invoice.pdf
	//                  <----------------------><---------->
	//                         <hash_file>        <filename> (optional)
	//
	//  GET /dl/contract/660d79500178f21ab3ffc357/contract.pdf
	//                   <----------------------><----------->
	//                          <hash_file>        <filename> (optional)
	//
	//  GET /dl/invoiceid/660d79500178f21ab3ffc357/invoice.pdf
	//                    <----------------------><----------->
	//                          <invoice_id>        <filename> (optional)
	//
	//  GET /dl/doc/660d79500178f21ab3ffc357/invoice.pdf
	//              <----------------------> <---------->
	//              <account_document's id>    <filename> (optional)
	//
	// The 'optional' above means that we return a 302 Redirect if <filename>
	// hasn't been given or is incorrect. That's super useful when the user only
	// has the hash file, then they can get the filename by following the
	// redirect. For example, if the user has the hash file:
	//
	//  GET /dl/invoice/660d79500178f21ab3ffc357     (ending / is optional)
	//
	// the user will redirected to:
	//
	//  GET /dl/invoice/660d79500178f21ab3ffc357/invoice.pdf
	mux.HandleFunc("/dl/", logRequest(func(w http.ResponseWriter, r *http.Request) {
		logutil.Debugf("download request: %s %s", r.Method, r.URL.Path)
		if r.Method != "GET" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get filename and hash file.
		urlPath, found := strings.CutPrefix(r.URL.Path, "/dl/")
		if !found {
			logutil.Errorf("was expecting a path like /dl/(invoice|contract)/<hash_file>/<filename> but got %q", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		parts := strings.Split(urlPath, "/")
		var typ, hashFile, fileNameInURL string
		switch len(parts) {
		case 2:
			typ = parts[0]
			hashFile = parts[1]
		case 3:
			typ = parts[0]
			hashFile = parts[1]
			fileNameInURL = parts[2]
		default:
			logutil.Errorf("invalid path %q, must be of: /dl/invoice/<hash_file>, /dl/invoiceid/<hash_file>, /dl/contract/<invoice_id> or /dl/doc/<account_document_id>. It may be followed by /<filename>", r.URL.Path)
			http.Error(w, "not found, URL must be of: /dl/invoice/<hash_file>, /dl/invoiceid/<hash_file>, /dl/contract/<invoice_id> or /dl/doc/<account_document_id>. It may be followed by /<filename>", http.StatusNotFound)
			return
		}

		var filePathReal string
		switch typ {
		case "invoice":
			expenses, err := db.GetExpensesByHashFileDB(context.Background(), sqlDB, hashFile)
			if err != nil || len(expenses) == 0 {
				logutil.Errorf("while getting expense by hash file: %v", err)
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			filePathReal = expenses[0].FilePath
		case "invoiceid":
			expenses, err := db.GetExpensesByInvoiceID(context.Background(), sqlDB, hashFile)
			if err != nil || expenses == nil {
				logutil.Errorf("while getting expense by invoice ID: %v", err)
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			filePathReal = expenses[0].FilePath
		case "contract":
			doc, err := db.GetSupplierContractByHashFileDB(context.Background(), sqlDB, hashFile)
			if err != nil {
				logutil.Errorf("while getting document by hash file: %v", err)
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			filePathReal = doc.FilePath
		case "doc":
			doc, err := db.GetAccountDocumentByHashFileDB(context.Background(), sqlDB, hashFile)
			if err != nil {
				logutil.Errorf("while getting account document by hash file: %v", err)
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			filePathReal = doc.FilePath
		default:
			http.Error(w, "not found, URL must start with either /dl/invoice/, /dl/invoiceid/, /dl/contract/ or /dl/doc/", http.StatusNotFound)
			logutil.Errorf("invalid path %q, must start with /dl/invoice/, /dl/invoiceid/, /dl/contract/ or /dl/doc/", r.URL.Path)
			return
		}

		// Let's redirect if the file path in the URL is not the same as the
		// real file path. The filePath may contain a relative path, so we only
		// keep the filename and remove the directory part.
		fileNameReal := path.Base(filePathReal)
		if fileNameInURL != fileNameReal {
			http.Redirect(w, r, "/dl/"+typ+"/"+hashFile+"/"+fileNameReal, http.StatusFound)
			return
		}

		// Otherwise, let's serve the file.
		logutil.Infof("serving file %q for %s", filePathReal, r.RemoteAddr)
		http.ServeFile(w, r, filePathReal)
	}))

	mux.HandleFunc("/", logRequest(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if r.Method != "GET" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		filterParam := r.URL.Query().Get("filter")
		searchParam := r.URL.Query().Get("search")

		const (
			filterShowAll  = ""
			filterExpenses = "expenses"
			filterMissions = "missions"
			filterVisits   = "visits" // Account documents with the category "reportVisit"
		)

		var f filter
		switch filterParam {
		case filterShowAll:
			f = filter{} // Zero value = show all.
		case filterExpenses:
			f = filter{HideExpenses: false, HideMissions: true, HideVisits: true}
		case filterMissions:
			f = filter{HideExpenses: true, HideMissions: false, HideVisits: true}
		case filterVisits:
			f = filter{HideExpenses: true, HideMissions: true, HideVisits: false}
		default:
			w.WriteHeader(http.StatusInternalServerError)
			tmlpErr.Execute(w, tmlpErrData{Error: fmt.Sprintf("Invalid filter: %q", filterParam), Version: version})
			return
		}

		f.Search = searchParam

		filteredItems, err := fetchFromDB(ctx, sqlDB, f)
		if err != nil {
			logutil.Errorf("while listing: %v", err)

			w.WriteHeader(http.StatusInternalServerError)
			tmlpErr.Execute(w, tmlpErrData{Error: fmt.Sprintf("Error while listing: %s", err), Version: version})

			return
		}

		w.Header().Set("Content-Type", "text/html")

		var statusMsg string
		when, err := lastSync()
		switch {
		case when.IsZero():
			statusMsg = "Aucune synchro n'a été faite."
		case err != nil:
			statusMsg = fmt.Sprintf("La dernière synchro a échoué il y a %s. Erreur : %v", time.Since(when).Truncate(time.Second), err)
		default:
			statusMsg = fmt.Sprintf("La dernière synchro a réussi il y a %s.", time.Since(when).Truncate(time.Second))
		}

		err = tmpl.Execute(w, tmlpData{
			BasePath:   basePath,
			SyncStatus: statusMsg,
			NtfyTopic:  *ntfyTopic,
			Items:      filteredItems,
			Version:    version + " (" + date + ")",
			Filter:     filterParam,
			Search:     searchParam,
		})
		if err != nil {
			logutil.Errorf("executing template: %v", err)
			return
		}
	}))

	mux.HandleFunc("/coowners", coownersEndpoint(client, uuid))

	mux.HandleFunc("/cloudmailingwebhook", logRequest(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		message, err := cloudmailin.ParseIncoming(r.Body)
		if err != nil {
			http.Error(w, "while parsing message: "+err.Error(), http.StatusUnprocessableEntity)
			return
		}

		// Output the first instance of the message-id in the headers to show
		// that we correctly parsed the message. We could also use the helper
		// message.Headers.MessageID().
		logutil.Infof("received message: message-id %s, sub: %s", message.Headers.MessageID(), message.Headers.Subject())

		tx, err := sqlDB.Begin()
		if err != nil {
			http.Error(w, "while starting transaction: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()

		logutil.Infof("message: %#v", message)
	}))

	return nil
}

// Zero value = show all.
type filter struct {
	HideExpenses bool
	HideMissions bool
	HideVisits   bool
	Search       string
}

func fetchFromDB(ctx context.Context, sqlDB *sql.DB, f filter) ([]MissionOrExpense, error) {
	var missions []db.MissionDB
	var err error

	if !f.HideMissions {
		missions, err = db.GetMissionsDB(ctx, sqlDB)
		if err != nil {
			return nil, fmt.Errorf("while listing missions: %w", err)
		}
	}

	var expenses []db.ExpenseDocumentDB
	if !f.HideExpenses {
		expenses, err = db.GetExpensesDB(ctx, sqlDB)
		if err != nil {
			return nil, fmt.Errorf("while listing expenses: %w", err)
		}
	}

	var accDocs []db.AccountDocumentDB
	if !f.HideVisits {
		accDocs, err = db.GetAccountDocumentsDB(ctx, sqlDB)
		if err != nil {
			return nil, fmt.Errorf("while listing account documents: %w", err)
		}
	}

	combined := combineAndSort(missions, expenses, accDocs)

	// Apply search filter if provided
	if f.Search != "" {
		combined = filterBySearch(combined, f.Search)
	}

	return combined, nil
}

func combineAndSort(missions []db.MissionDB, expenses []db.ExpenseDocumentDB, accDocs []db.AccountDocumentDB) []MissionOrExpense {
	// Combine them.
	var combined []MissionOrExpense
	for _, m := range missions {
		m := m
		combined = append(combined, MissionOrExpense{Mission: &m})
	}
	for _, e := range expenses {
		e := e
		combined = append(combined, MissionOrExpense{Expense: &e})
	}
	for _, a := range accDocs {
		a := a
		combined = append(combined, MissionOrExpense{AccountDocument: &a})
	}

	sort.Slice(combined, func(i, j int) bool {
		di, dj := time.Time{}, time.Time{}
		if combined[i].Mission != nil {
			di = combined[i].Mission.StartedAt
		}
		if combined[i].Expense != nil {
			di = combined[i].Expense.Date
		}
		if combined[i].AccountDocument != nil {
			di = combined[i].AccountDocument.CreatedAt
		}

		if combined[j].Mission != nil {
			dj = combined[j].Mission.StartedAt
		}
		if combined[j].Expense != nil {
			dj = combined[j].Expense.Date
		}
		if combined[j].AccountDocument != nil {
			dj = combined[j].AccountDocument.CreatedAt
		}
		return di.After(dj)
	})

	return combined
}

// filterBySearch filters the combined items based on the search query
// It searches in filename, label, and description fields
func filterBySearch(items []MissionOrExpense, search string) []MissionOrExpense {
	if search == "" {
		return items
	}

	// Convert search to lowercase for case-insensitive search
	searchLower := strings.ToLower(search)
	var filtered []MissionOrExpense

	for _, item := range items {
		var matches bool

		if item.Mission != nil {
			m := item.Mission
			// Search in label, description, and work order filenames
			if strings.Contains(strings.ToLower(m.Label), searchLower) ||
				strings.Contains(strings.ToLower(m.Description), searchLower) {
				matches = true
			}

			// Search in work order filenames and supplier names
			for _, wo := range m.WorkOrders {
				if strings.Contains(strings.ToLower(wo.Supplier.Name), searchLower) {
					matches = true
					break
				}
				for _, doc := range wo.Supplier.Documents {
					if strings.Contains(strings.ToLower(doc.FilePath), searchLower) {
						matches = true
						break
					}
				}
				if matches {
					break
				}
			}
		}

		if item.Expense != nil {
			e := item.Expense
			// Search in label, filename
			if strings.Contains(strings.ToLower(e.Label), searchLower) ||
				strings.Contains(strings.ToLower(e.Filename()), searchLower) {
				matches = true
			}
		}

		if item.AccountDocument != nil {
			a := item.AccountDocument
			// Search in category, filename, mime type
			if strings.Contains(strings.ToLower(a.CategoryFrench()), searchLower) ||
				strings.Contains(strings.ToLower(a.Filename()), searchLower) ||
				strings.Contains(strings.ToLower(a.MimeType), searchLower) {
				matches = true
			}
		}

		if matches {
			filtered = append(filtered, item)
		}
	}

	return filtered
}
