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
