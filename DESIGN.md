---
version: alpha
name: "OpenProof Identity Workbench"
description: "A bilingual developer tool for inspecting and exercising identity ceremonies without hiding protocol state."
colors:
  primary: "#6957E8"
  primary-dark: "#5543D6"
  navigation: "#0D172B"
  canvas: "#F5F7FB"
  surface: "#FFFFFF"
  text: "#101828"
  muted: "#667085"
  border: "#E2E7EF"
  success: "#0E7654"
  warning: "#A15C07"
  danger: "#C9364C"
typography:
  sans:
    fontFamily: "Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Tahoma, sans-serif"
  mono:
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace"
rounded:
  DEFAULT: "0.75rem"
  sm: "0.5rem"
  md: "0.75rem"
  lg: "1rem"
spacing:
  section-gap: "1.75rem"
  page-max: "96.25rem"
components:
  button:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.surface}"
  button-pressed:
    backgroundColor: "{colors.primary-dark}"
    textColor: "{colors.surface}"
  card:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
  canvas:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.text}"
  input:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
  input-placeholder:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.muted}"
  navigation:
    backgroundColor: "{colors.navigation}"
    textColor: "{colors.surface}"
  navigation-selected:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.surface}"
  divider:
    backgroundColor: "{colors.border}"
    textColor: "{colors.text}"
  status-success:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.success}"
  status-warning:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.warning}"
  status-danger:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.danger}"
  code-panel:
    backgroundColor: "{colors.navigation}"
    textColor: "{colors.surface}"
---

# OpenProof Identity Workbench Design System

## Overview

### Creative North Star

An instrument panel for identity protocols: calm enough for repeated engineering work, explicit enough that every security boundary and state transition remains visible.

### Product context and register

- **Audience and primary job:** Application and identity engineers use the Web Lab and native QML client to exercise OpenProof ceremonies, inspect exact protocol payloads, and diagnose configuration.
- **Target market(s) and evidence:** The product is market-neutral developer infrastructure. Repository UI and documentation provide first-class Persian and English interfaces.
- **Locale(s) and language policy:** Persian is RTL and English is LTR; technical values retain LTR direction. Every new user-facing string ships in both languages in the same change.
- **Usage scene:** Desktop-first local development, moderately dense, frequent and diagnostic. Responsive web layouts must remain usable on narrow screens.
- **Register:** Product/tool UI. Protocol messages, endpoint paths, addresses, FIDs, timestamps, and response bodies are never presented as marketing decoration.
- **Memorable signature:** A restrained violet identity accent against a dark navy navigation rail.
- **Restraint:** Forms, protocol previews, errors, and verification results use familiar controls and stable layouts.
- **Anti-references:** No crypto trading aesthetic, neon/Web3 spectacle, glassmorphism, gratuitous gradients, or card-per-line fragmentation.
- **Token ownership/runtime mapping:** This file records the implemented system. Web tokens live in `scripts/local-demo-portal-v3.css`; QML tokens live at the root of `examples/qml-identity-client/Main.qml`. Visual verification and tests are the drift gate.

## Colors

Violet is reserved for selection, primary action, and protocol identity. Navy owns persistent navigation. White and cool gray surfaces carry content; borders establish most hierarchy. Green, amber, and red are semantic and never used decoratively. Focus rings use a translucent primary color and must remain visible on every interactive control.

## Typography

The UI uses the system-capable sans stack so Persian and Latin remain native to the platform. Technical content uses the mono stack, LTR direction, and left alignment. Headings use sentence case; labels are concise and never rely on all-caps to convey hierarchy. Mixed-script lines isolate technical spans rather than reversing the whole sentence.

## Layout

Desktop web uses a 296px persistent rail and a centered main region up to 1540px. QML mirrors the rail/content relationship. Forms use one or two columns based on available width and collapse without horizontal scrolling. Busy, success, and error content reserve space so controls do not jump. Protocol previews may scroll internally but must not resize through a drag handle.

## Elevation & Depth

Borders and tonal surfaces are primary. Shadows are low-contrast and limited to floating navigation feedback, focused panels, and overlays. Dense protocol and response panels use dark solid surfaces. Elevation is forbidden as decoration around every field or fact.

## Shapes

Controls use 11–12px radii; content surfaces use 16px; icon containers use 9–14px. Pills are limited to compact statuses and claims. Borders are one pixel and exceptions must communicate focus, selection, or validation.

## Components

### Foundational visual states

Interactive components provide default, hover, focus-visible, pressed, selected, disabled, read-only, busy, success, warning, and error states. Busy actions keep their width and replace only the leading icon with the shared spinner. Errors remain adjacent to the affected control and a summary is used when multiple fields fail.

### Buttons and actions

One primary action advances a ceremony. Secondary actions inspect, copy, open tools, or reset. Destructive actions are visually separated. Icon-only buttons require accessible names; workflow actions retain text labels in both locales.

### Navigation and data display

The stable rail identifies the current page with tonal fill, accent edge, and icon treatment. Status badges pair color with text or icon. Request traces and protocol facts favor aligned rows over independent cards.

### Forms and overlays

Labels precede controls and required status is explicit. Validation occurs on submit and clears as the value changes. Read-only messages remain selectable. Modal focus is trapped and restored; overlays are reserved for endpoint selection and focused tasks.

### Iconography

Web uses Material Symbols Rounded; QML uses compact text glyphs from the existing native client. Icons support labels and never replace unfamiliar security concepts.

### Motion

Motion communicates page entry, hover, and busy feedback in roughly 150–220ms. It is interruptible, never blocks a request, and must be removed when reduced motion is requested.

### Content and data visualization

Voice is direct and diagnostic. Copy names the exact protocol operation and explains trust boundaries. FIDs, chain IDs, addresses, HTTP status, and timings use locale-independent technical formatting; explanatory prose follows the active locale.

## Do's and Don'ts

- **Do:** Keep the exact signed message, nonce, chain, FID resource, and signer authorization visible during SIWF testing.
- **Do:** Preserve the same action vocabulary and semantic colors across Web Lab and QML.
- **Don't:** Suggest that OpenProof receives or stores a user's private key.
- **Don't:** imply full Farcaster social-data support when the implemented capability is authentication and identity linking.
