# AGENTS.md

## Project

This repository currently uses the internal/project name `GabiUnhas`.

The final SaaS product and brand will be called:

**Elleva**

Do not rename infrastructure, repository identifiers, deployment URLs,
Supabase projects, branches, or OAuth URLs merely for branding purposes
unless explicitly requested.

Visible product branding may gradually migrate from GabiUnhas /
Gabriela Alves Nails to Elleva.

---

## Product vision

Elleva is being developed as a SaaS business management platform for
beauty professionals.

Target professionals include:

- Nail artists
- Hair stylists
- Lash artists
- Estheticians
- Beauty studios

The current application is the first working version and is being
migrated from a personal nail-management app into a multi-user SaaS.

Main areas currently implemented:

- Authentication
- Appointment scheduling
- Availability validation
- Earnings dashboard
- Expense management
- Optional Google Calendar integration

---

## Current technology

Frontend:

- Single `index.html`
- HTML
- CSS
- Vanilla JavaScript

Backend:

- Supabase Auth
- Supabase PostgreSQL
- Supabase RLS
- Supabase Edge Functions

Deployment:

- Vercel

External integrations:

- Google Calendar API
- Google OAuth 2.0

---

## Git workflow

This is extremely important.

### Production branch

`main`

`main` is production.

The production application is actively used.

Do NOT:

- make experimental changes directly on `main`
- merge into `main` without explicit user approval
- push changes to `main` without explicit user approval
- rewrite production history
- force push

### Development branch

Current migration/development branch:

`migration/supabase-vercel`

All current development must be performed on this branch unless
explicitly instructed otherwise.

Before editing, always check:

```bash
git status
git branch --show-current