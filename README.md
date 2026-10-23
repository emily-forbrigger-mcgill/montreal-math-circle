# Montreal Math Circle Website

The official website for the **Montreal Math Circle**.

This repository powers [montrealmathcircle.com](https://montrealmathcircle.com/), built using the [Astro](https://astro.build/) framework. It features a modern, responsive layout, Bento-grid component architecture, and structured sections for schedule logistics, event announcements, learning resources, and team profiles.

---

## 🎨 Branding & Custom Styling Notice

- **Current Styling:** The site currently incorporates temporary McGill University visual accents (such as McGill Burgundy `#a81b24`, Space Grotesk headers, Plus Jakarta Sans body font, and Fira Code for technical tags).
- **Upcoming Brand Transition:** The organization is transitioning toward its own distinct identity and visual branding. Future maintainers can easily adjust global design tokens (colors, logo assets, typography) inside `src/layouts/Layout.astro` without touching individual page code.

---

## 📁 Repository Structure

```text
/
├── public/
│   ├── mmc-logo-v1.png          # Main organization logo & brand graphic
│   ├── mmc-logo-header.png      # Main organization logo & brand graphic
│   └── favicon.svg              # Browser tab icon (configured in Layout.astro)
├── src/
│   ├── components/              # Modular UI components (cards, badges, grids)
│   ├── layouts/
│   │   └── Layout.astro         # Main global page shell (Head, Nav, Footer, CSS Variables)
│   └── pages/
│       ├── index.astro          # Home page (Hero, featured event, logistics, partner strip)
│       ├── schedule.astro       # Event calendar, timeline, and Burnside venue details
│       ├── resources.astro      # Problem sets, handouts, solutions, and category filters
│       ├── programs.astro       # Overview of workshops, conferences, and student tracks
│       └── about.astro          # Mission statement, values, and leadership/mentor profiles
├── package.json
└── astro.config.mjs

## 🛠️ Maintainer's Guide: How to Update Content

This guide provides ready-to-use code snippets for future webmasters and organizers to update schedules, problem sets, team profiles, and brand styling.

```astro
// ============================================================================
// 1. UPDATING THE EVENT SCHEDULE (src/pages/schedule.astro)
// ============================================================================
// Add a new event card inside <div class="timeline">:
<article class="timeline-card">
    <div class="timeline-badge-column">
        <span class="date-badge">October 15, 2026</span>
    </div>
    <div class="timeline-content">
        <h3>Graph Theory & Combinatorics Workshop</h3>
        <p class="speaker-text">Guest Speaker: Prof. Alex Smith (McGill)</p>
    </div>
</article>

// Update venue details inside <aside class="sidebar">:
<div class="detail-row">
    <span class="detail-label">Building:</span>
    <span class="detail-value">Burnside Hall</span>
</div>
<div class="detail-row">
    <span class="detail-label">Room:</span>
    <span class="detail-value">Room 1205, 12th Floor</span>
</div>

// ============================================================================
// 2. ADDING PROBLEM SETS & HANDOUTS (src/pages/resources.astro)
// ============================================================================
// Step A: Save PDF files into /public/handouts/ (e.g., /public/handouts/week1.pdf).
// Step B: Add a new card inside <div class="resource-grid">:
<article class="resource-card">
    <div class="card-top">
        <div class="card-badge-row">
            <span class="session-tag">Week 4</span>
            <!-- Difficulty classes: level-intro, level-inter, level-adv -->
            <span class="difficulty-badge level-inter">Intermediate</span>
        </div>
        <h3>Intro to Invariants & Monovariants</h3>
        <p>Problem set covering invariant quantities in games and grid puzzles.</p>
    </div>
    <div class="card-meta">
        <span class="file-info">PDF • 240 KB</span>
        <div class="card-actions">
            <a href="/handouts/week4-handout.pdf" class="download-link primary-action" target="_blank">
                <span>Handout</span>
            </a>
            <a href="/handouts/week4-solutions.pdf" class="download-link secondary-action" target="_blank">
                <span>Solutions</span>
            </a>
        </div>
    </div>
</article>

// ============================================================================
// 3. UPDATING TEAM & MENTOR PROFILES (src/pages/about.astro)
// ============================================================================
// Add a new member card inside <div class="team-grid">:
<article class="team-card">
    <!-- Save photo in /public/team/ (e.g., /public/team/jane-doe.jpg) -->
    <img src="/team/jane-doe.jpg" alt="Jane Doe" class="team-avatar" />
    <div class="team-info">
        <h3>Jane Doe</h3>
        <span class="team-role">Head Coordinator</span>
        <p class="team-bio">U3 Physics & Math student at McGill studying topology.</p>
        <div class="team-links">
            <a href="mailto:jane.doe@montrealmathcircle.com" class="team-link">Contact Email</a>
        </div>
    </div>
</article>

// ============================================================================
// 4. UPDATING BRAND COLORS & DESIGN TOKENS (src/layouts/Layout.astro)
// ============================================================================
// When updating organization branding, edit the :root CSS block in Layout.astro:
:root { 
    --primary: #a81b24;          /* Main Brand Color */
    --primary-light: #fcf1f2;    /* Soft Accent Background */
    --dark: #18181b;             /* Heading & Dark Text Color */
    --text-muted: #64748b;       /* Subtitle & Meta Text Color */
    --border-color: #e2e8f0;     /* Card Border Lines */
    
    /* Font Variables */
    --font-heading: 'Space Grotesk', system-ui, sans-serif;
    --font-body: 'Plus Jakarta Sans', system-ui, sans-serif;
    --font-mono: 'Fira Code', monospace;
}
